/** Minimal toggle switch. Replaces @radix-ui/react-switch to avoid the dep. */

interface ToggleProps {
  checked: boolean;
  onCheckedChange: (value: boolean) => void;
  disabled?: boolean;
}

export function Toggle({ checked, onCheckedChange, disabled = false }: ToggleProps) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-disabled={disabled}
      onClick={disabled ? undefined : () => onCheckedChange(!checked)}
      className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 focus-visible:outline-none"
      style={{
        background: checked ? "var(--amber)" : "var(--panel-light)",
        border: `1px solid ${checked ? "var(--amber-dim)" : "var(--border-md)"}`,
        opacity: disabled ? 0.5 : 1,
        cursor: disabled ? "not-allowed" : "pointer",
      }}
    >
      <span
        className="inline-block h-3.5 w-3.5 rounded-full transition-transform duration-200"
        style={{
          background: checked ? "#fff" : "var(--steel-dim)",
          transform: checked ? "translateX(17px)" : "translateX(3px)",
        }}
      />
    </button>
  );
}
