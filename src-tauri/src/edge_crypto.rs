//! dx150-edge-v1 加密网关客户端。
//!
//! 2026-11-09 上游升级后，播放地址（`/api/videos/:id/play` 等）被划入加密网关的
//! `playback` scope：旧的明文 `/api/edge/request` 对这些路径不再返回媒体字段，
//! 必须先与 `/api/playback/request` 做 ECDH 握手，再用 AES-256-GCM 加密信封取址。
//! 协议参考官网 `/static/web/js/edge-api-crypto.js`：
//!
//! 1. `hello`：客户端生成 ECDH P-256 密钥对，上送原始公钥（base64url）；
//!    服务端回 `kid` / `sid` / `site` / `server_pub` / `salt` / `server_time` / `expires_at`。
//! 2. 密钥派生：shared = ECDH(client_priv, server_pub)；
//!    `HKDF-SHA256(shared, salt=hello.salt, info="{protocol}\n{scope}\n{site}\n{kid}\n{sid}\n{direction}")`
//!    派生两把 AES-256-GCM 密钥（req 加密 / res 解密）。
//! 3. 业务调用：明文 JSON `{request:{method,path,body,content_type}, authorization?}`
//!    用 req 密钥加密（nonce = 12 字节，后 4 字节为大端 seq；AAD =
//!    `{info}\n{direction}\n{seq}\n{ts}`），信封 `{v:1,type:'call',kid,sid,seq,ts,ciphertext}`。
//! 4. 响应信封 `{v:1,type:'result',...,ciphertext}` 用 res 密钥解密，
//!    内层 `{status, headers, body(base64)}` 模拟真实 HTTP 响应。
//!
//! 另外新版取址返回 `cdn` 配置（m3u8 分片需要带 `x-cdn-auth` 头），缓存在本模块，
//! 由 `media.rs` 的代理请求按 URL 类型附加。

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use once_cell::sync::Lazy;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Mutex;
use std::time::Duration;

const PROTOCOL: &str = "dx150-edge-v1";
const SCOPE: &str = "playback";
const MAX_SEQUENCE: u32 = 16384;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/* ───────────────────────── base64url ───────────────────────── */

fn b64url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(value: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "加密响应编码无效".to_string())
}

fn b64_decode(value: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| "加密响应编码无效".to_string())
}

/* ───────────────────────── CDN 认证头缓存 ───────────────────────── */

/// 新版取址返回的 CDN 签名头。官方播放器按 URL 类型给分片请求加头
/// （`xhrSetup`）：m3u8 受 `m3u8Enabled` 控制，ts/m4s/key 受 `otherEnabled` 控制。
#[derive(Clone, Debug)]
pub struct CdnAuth {
    pub m3u8_enabled: bool,
    pub other_enabled: bool,
    pub key: String,
    pub value: String,
    pub app: String,
}

static CDN_AUTH: Lazy<Mutex<Option<CdnAuth>>> = Lazy::new(|| Mutex::new(None));

/// 从取址响应的 `cdn` 对象更新认证头缓存（字段缺失/为空时不覆盖旧值）。
pub fn store_cdn_auth(cdn: Option<&Value>) {
    let Some(cdn) = cdn else { return };
    let next = CdnAuth {
        m3u8_enabled: cdn.get("m3u8Enabled").and_then(Value::as_bool).unwrap_or(false),
        other_enabled: cdn.get("otherEnabled").and_then(Value::as_bool).unwrap_or(false),
        key: cdn.get("authKey").and_then(Value::as_str).unwrap_or("").to_string(),
        value: cdn.get("authValue").and_then(Value::as_str).unwrap_or("").to_string(),
        app: cdn.get("app").and_then(Value::as_str).unwrap_or("").to_string(),
    };
    if next.key.is_empty() || next.value.is_empty() || next.app.is_empty() {
        return;
    }
    if let Ok(mut guard) = CDN_AUTH.lock() {
        *guard = Some(next);
    }
}

/// 按 URL 判断需要附加的 CDN 认证头（官方 `xhrSetup` 的 Rust 版）。
pub fn cdn_headers_for(url: &str) -> Vec<(String, String)> {
    let Some(auth) = CDN_AUTH.lock().ok().and_then(|g| g.clone()) else {
        return Vec::new();
    };
    let path = url.split('?').next().unwrap_or(url).to_ascii_lowercase();
    let is_m3u8 = path.ends_with(".m3u8");
    let is_other = path.ends_with(".ts") || path.ends_with(".m4s") || path.ends_with(".key");
    let hit = (is_m3u8 && auth.m3u8_enabled) || (is_other && auth.other_enabled);
    if !hit {
        return Vec::new();
    }
    vec![(auth.key, auth.value), ("x-cdn-app".to_string(), auth.app)]
}

/* ───────────────────────── 加密会话 ───────────────────────── */

struct Session {
    info: String,
    kid: String,
    sid: String,
    request_key: Vec<u8>,
    response_key: Vec<u8>,
    clock_offset: i64,
    expires_at: i64,
    sequence: u32,
}

impl Session {
    fn valid(&self) -> bool {
        self.sequence < MAX_SEQUENCE && self.expires_at > unix_now() + 5
    }
}

static SESSION: Lazy<tokio::sync::Mutex<Option<Session>>> = Lazy::new(|| tokio::sync::Mutex::new(None));

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn valid_token(value: &str, what: &str, max: usize, min: usize) -> Result<(), String> {
    if value.len() < min || value.len() > max || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err(format!("加密握手响应无效（{what}）"));
    }
    Ok(())
}

/// hello 握手 + 密钥派生。
async fn open_session(origin: &str) -> Result<Session, String> {
    let secret = EphemeralSecret::random(&mut OsRng);
    let client_pub = secret.public_key().to_encoded_point(false);
    let hello = {
        let url = format!("{origin}/api/playback/request");
        let (status, value) = crate::net::post_json(
            &url,
            &json!({"v": 1, "type": "hello", "client_pub": b64url_encode(client_pub.as_bytes())}),
            REQUEST_TIMEOUT,
        )
        .await?;
        if status != 200 {
            return Err(format!("加密握手失败（HTTP {status}）"));
        }
        value
    };
    if hello.get("v").and_then(Value::as_i64) != Some(1)
        || hello.get("type").and_then(Value::as_str) != Some("hello")
    {
        return Err("加密握手响应无效".into());
    }
    let kid = hello.get("kid").and_then(Value::as_str).unwrap_or("").to_string();
    let sid = hello.get("sid").and_then(Value::as_str).unwrap_or("").to_string();
    let site = hello.get("site").and_then(Value::as_str).unwrap_or("").to_string();
    let server_pub = hello.get("server_pub").and_then(Value::as_str).unwrap_or("");
    let salt = hello.get("salt").and_then(Value::as_str).unwrap_or("");
    let server_time = hello.get("server_time").and_then(Value::as_i64).unwrap_or(0);
    let expires_at = hello.get("expires_at").and_then(Value::as_i64).unwrap_or(0);
    valid_token(&kid, "kid", 64, 1)?;
    valid_token(&sid, "sid", 128, 16)?;
    if site.is_empty() || site.len() > 256 {
        return Err("加密握手响应无效（site）".into());
    }
    if expires_at <= server_time || expires_at - server_time > 600 {
        return Err("加密握手响应无效（有效期）".into());
    }
    let salt_bytes = b64url_decode(salt)?;
    if salt_bytes.len() != 32 {
        return Err("加密握手响应无效（salt）".into());
    }
    let server_key = p256::PublicKey::from_sec1_bytes(&b64url_decode(server_pub)?)
        .map_err(|_| "加密握手响应无效（server_pub）".to_string())?;
    let shared = secret.diffie_hellman(&server_key).raw_secret_bytes().to_vec();
    let info = format!("{PROTOCOL}\n{SCOPE}\n{site}\n{kid}\n{sid}");
    let hkdf = Hkdf::<Sha256>::new(Some(&salt_bytes), &shared);
    let mut request_key = vec![0u8; 32];
    let mut response_key = vec![0u8; 32];
    hkdf.expand(format!("{info}\nreq").as_bytes(), &mut request_key)
        .map_err(|_| "密钥派生失败".to_string())?;
    hkdf.expand(format!("{info}\nres").as_bytes(), &mut response_key)
        .map_err(|_| "密钥派生失败".to_string())?;
    let now = unix_now();
    Ok(Session {
        info,
        kid,
        sid,
        request_key,
        response_key,
        clock_offset: server_time - now,
        expires_at: now + (expires_at - server_time),
        sequence: 0,
    })
}

/// 会话失效原因：密钥过期 / 响应不匹配 / 解密失败，可重握手一次。
enum Step {
    Done(Result<Value, String>),
    Rehandshake,
}

fn aad(info: &str, direction: &str, seq: u32, ts: i64) -> Vec<u8> {
    format!("{info}\n{direction}\n{seq}\n{ts}").into_bytes()
}

fn nonce_for(seq: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[8..].copy_from_slice(&seq.to_be_bytes());
    iv
}

fn encrypt_packet(key: &[u8], iv: &[u8], aad_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "AES 密钥无效".to_string())?;
    cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload { msg: plaintext, aad: aad_bytes },
        )
        .map_err(|_| "信封加密失败".to_string())
}

fn decrypt_packet(key: &[u8], iv: &[u8], aad_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 16 {
        return Err("加密响应过短".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "AES 密钥无效".to_string())?;
    cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload { msg: data, aad: aad_bytes },
        )
        .map_err(|_| "信封解密失败".to_string())
}

/// 通过加密网关发起一次业务请求，返回解密后的响应 JSON。
///
/// 整个调用持有会话锁：序列号必须单调递增，且重握手不能并发竞争。
/// 会话过期 / 响应不匹配 / 解密失败时自动重握手并重试一次。
async fn gateway_call(origin: &str, request: Value, token: Option<&str>) -> Result<Value, String> {
    let mut guard = SESSION.lock().await;
    let mut retried = false;
    loop {
        if !guard.as_ref().is_some_and(Session::valid) {
            *guard = Some(open_session(origin).await?);
        }
        let session = guard.as_mut().expect("会话刚建立");
        session.sequence += 1;
        let seq = session.sequence;
        let ts = unix_now() + session.clock_offset;
        let info = session.info.clone();
        let kid = session.kid.clone();
        let sid = session.sid.clone();
        let request_key = session.request_key.clone();
        let response_key = session.response_key.clone();
        let packet = if let Some(t) = token.filter(|t| !t.is_empty()) {
            json!({"request": request, "authorization": format!("Bearer {t}")})
        } else {
            json!({"request": request})
        };
        let plaintext = serde_json::to_vec(&packet).map_err(|e| e.to_string())?;
        let iv = nonce_for(seq);
        let ciphertext = encrypt_packet(&request_key, &iv, &aad(&info, "req", seq, ts), &plaintext)?;
        let url = format!("{origin}/api/playback/request");
        let call = async {
            let posted = crate::net::post_json(
                &url,
                &json!({
                    "v": 1, "type": "call",
                    "kid": kid, "sid": sid,
                    "seq": seq, "ts": ts,
                    "ciphertext": b64url_encode(&ciphertext),
                }),
                REQUEST_TIMEOUT,
            )
            .await;
            let (status, result) = match posted {
                Ok(pair) => pair,
                Err(e) => return Step::Done(Err(e)),
            };
            if status != 200 {
                if result.get("error").and_then(Value::as_str) == Some("session_expired") {
                    return Step::Rehandshake;
                }
                return Step::Done(Err(format!("加密接口请求失败（HTTP {status}）")));
            }
            if result.get("v").and_then(Value::as_i64) != Some(1)
                || result.get("type").and_then(Value::as_str) != Some("result")
                || result.get("sid").and_then(Value::as_str) != Some(sid.as_str())
                || result.get("kid").and_then(Value::as_str) != Some(kid.as_str())
            {
                return Step::Rehandshake;
            }
            let Ok(data) = b64url_decode(result.get("ciphertext").and_then(Value::as_str).unwrap_or("")) else {
                return Step::Rehandshake;
            };
            let Ok(plain) = decrypt_packet(&response_key, &iv, &aad(&info, "res", seq, ts), &data) else {
                return Step::Rehandshake;
            };
            let Ok(inner) = serde_json::from_slice::<Value>(&plain) else {
                return Step::Done(Err("加密接口响应格式无效".into()));
            };
            let inner_status = inner.get("status").and_then(Value::as_i64).unwrap_or(0);
            if !(200..=599).contains(&inner_status) {
                return Step::Done(Err("加密接口响应格式无效".into()));
            }
            Step::Done(Ok(inner))
        }
        .await;
        match call {
            Step::Done(outcome) => return outcome,
            Step::Rehandshake => {
                if retried {
                    return Err("加密会话已失效".into());
                }
                *guard = None;
                retried = true;
            }
        }
    }
}

/// 播放取址：模拟一次对 `path` 的 HTTP 请求，返回业务 JSON。
pub async fn playback_request(
    origin: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> Result<Value, String> {
    let inner = gateway_call(
        origin,
        json!({"method": method, "path": path, "body": "", "content_type": ""}),
        token,
    )
    .await?;
    let status = inner.get("status").and_then(Value::as_i64).unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}"));
    }
    let body = inner.get("body").and_then(Value::as_str).unwrap_or("");
    let bytes = b64_decode(body)?;
    serde_json::from_slice(&bytes).map_err(|_| "播放接口响应不是有效 JSON".to_string())
}

/// 把新版取址响应映射回旧版 `video_url` 结构（前端只需要 `video_url`）。
///
/// 同时把 `cdn` 配置写入缓存，供媒体代理附加认证头。
pub fn map_play_response(response: Value) -> Value {
    let data = response
        .get("data")
        .filter(|d| d.is_object())
        .cloned()
        .unwrap_or_else(|| response.clone());
    let streams = data.get("streams");
    let main = streams
        .and_then(|s| s.get("main"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let hevc = streams
        .and_then(|s| s.get("hevc"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    store_cdn_auth(data.get("cdn"));
    let mut out = data.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("video_url".into(), json!(main));
        obj.insert("video_url_hevc".into(), json!(hevc));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_carries_big_endian_sequence_in_tail() {
        let iv = nonce_for(7);
        assert!(iv[..8].iter().all(|b| *b == 0));
        assert_eq!(&iv[8..], &[0, 0, 0, 7]);
    }

    #[test]
    fn roundtrip_encrypt_decrypt_matches_webcrypto_layout() {
        // aes-gcm crate 的输出与 WebCrypto 一致：密文尾部追加 16 字节 tag。
        let key = [0x42u8; 32];
        let iv = nonce_for(3);
        let aad = aad("info", "req", 3, 1700000000);
        let ct = encrypt_packet(&key, &iv, &aad, b"{\"a\":1}").expect("encrypt");
        assert_eq!(ct.len(), 16 + 5);
        let pt = decrypt_packet(&key, &iv, &aad, &ct).expect("decrypt");
        assert_eq!(pt, b"{\"a\":1}");
    }

    #[test]
    fn cdn_headers_follow_official_url_rules() {
        let auth = CdnAuth {
            m3u8_enabled: true,
            other_enabled: false,
            key: "x-cdn-auth".into(),
            value: "sig".into(),
            app: "150".into(),
        };
        if let Ok(mut guard) = CDN_AUTH.lock() {
            *guard = Some(auth);
        }
        let m3u8 = cdn_headers_for("https://cdn.example/v/1.m3u8?auth_key=x");
        assert_eq!(m3u8.len(), 2);
        assert_eq!(m3u8[0].0, "x-cdn-auth");
        assert_eq!(m3u8[1].1, "150");
        assert!(cdn_headers_for("https://cdn.example/v/1.ts").is_empty());
        assert!(cdn_headers_for("https://other.example/1.m3u8").len() == 2);
        if let Ok(mut guard) = CDN_AUTH.lock() {
            *guard = None;
        }
    }

    #[test]
    fn map_play_response_keeps_new_fields_and_fills_video_url() {
        let response = json!({
            "data": {
                "mode": 1, "timestamp": 1, "manifest_method": "GET", "id": 12, "ep": 1,
                "cdn": {"m3u8Enabled": true, "otherEnabled": false, "authKey": "x-cdn-auth", "authValue": "v", "app": "150"},
                "streams": {"main": "https://cdn.example/a.m3u8", "hevc": "https://cdn.example/b.m3u8"}
            }
        });
        let mapped = map_play_response(response);
        assert_eq!(mapped["video_url"], "https://cdn.example/a.m3u8");
        assert_eq!(mapped["video_url_hevc"], "https://cdn.example/b.m3u8");
        assert_eq!(mapped["manifest_method"], "GET");
        assert_eq!(mapped["ep"], 1);
        let headers = cdn_headers_for("https://cdn.example/a.m3u8");
        assert_eq!(headers.len(), 2);
        if let Ok(mut guard) = CDN_AUTH.lock() {
            *guard = None;
        }
    }
}
