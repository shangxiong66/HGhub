import { getCurrentWindow } from "@tauri-apps/api/window";

const MAP: [string, string][] = [
  ["n", "North"], ["s", "South"], ["e", "East"], ["w", "West"],
  ["ne", "NorthEast"], ["nw", "NorthWest"], ["se", "SouthEast"], ["sw", "SouthWest"],
];

/** 无边框窗口的边缘拖拽缩放（Windows）。仅 Tauri WebView 内生效，纯浏览器直接不渲染。 */
export default function ResizeHandles() {
  // getCurrentWindow() 依赖 window.__TAURI_INTERNALS__.metadata，浏览器里不存在会抛错
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return null;
  const win = getCurrentWindow();
  return (
    <div className="pointer-events-none absolute inset-0 z-[70]">
      {MAP.map(([edge, dir]) => (
        <div key={edge}
          className={`win-resize win-resize-${edge} pointer-events-auto`}
          onPointerDown={(e) => {
            e.preventDefault();
            // ResizeDirection 在类型包里未导出，按字符串传入
            (win.startResizeDragging as unknown as (d: string) => Promise<void>)(dir).catch(() => {});
          }}
        />
      ))}
    </div>
  );
}