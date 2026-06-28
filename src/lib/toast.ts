import { toast, type ExternalToast } from "sonner";

function errorClipboardText(
  message: string,
  description?: ExternalToast["description"],
): string {
  if (typeof description === "string" && description.length > 0) {
    return `${message}\n${description}`;
  }
  return message;
}

function copyToastAction(text: string) {
  return {
    label: "Copy",
    onClick: () => void navigator.clipboard.writeText(text),
  };
}

/** Error toast with a Copy action for pasting into bug reports. */
export function toastError(message: string, options?: ExternalToast) {
  const text = errorClipboardText(message, options?.description);
  if (options?.action) {
    return toast.error(message, {
      ...options,
      cancel: options.cancel ?? copyToastAction(text),
    });
  }
  return toast.error(message, {
    ...options,
    action: copyToastAction(text),
  });
}
