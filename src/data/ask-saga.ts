import { createServerFn } from "@tanstack/react-start";

type Turn = { role: "user" | "assistant"; text: string };

export type AskSagaResult = { ok: true; text: string } | { ok: false; error: string };

export function parseTurns(input: unknown): Turn[] {
  if (typeof input !== "object" || input === null || !("messages" in input)) {
    throw new Error("Send a message list.");
  }
  const raw = (input as { messages: unknown }).messages;
  // The whole thread is sent so a later question can refer to an earlier one.
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 80) {
    throw new Error("Send between 1 and 80 messages.");
  }
  const messages: Turn[] = [];
  for (const item of raw) {
    if (typeof item !== "object" || item === null) throw new Error("Each message must have a role and text.");
    const role = (item as { role?: unknown }).role;
    const text = (item as { text?: unknown }).text;
    if ((role !== "user" && role !== "assistant") || typeof text !== "string") {
      throw new Error("Each message must have a role and text.");
    }
    const trimmed = text.trim();
    if (!trimmed || trimmed.length > 8000) throw new Error("Each message must be 1–8000 characters.");
    messages.push({ role, text: trimmed });
  }
  if (messages.at(-1)?.role !== "user") throw new Error("The latest message must be from the user.");
  return messages;
}

export const askSaga = createServerFn({ method: "POST" })
  .validator((input: unknown) => ({ messages: parseTurns(input) }))
  .handler(async ({ data }): Promise<AskSagaResult> => {
    const { answer } = await import("./ask-saga.server");
    return answer(data.messages);
  });
