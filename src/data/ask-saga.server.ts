import { readFileSync } from "node:fs";
import { join } from "node:path";
import { evidencePack } from "./log-summary.server";

// Flash often returns 503 or an empty body. Lite answered when flash did not.
// 3.8-flash is the last try. Lite rejects thinkingConfig, so only flash models send it.
const MODELS: { id: string; thinking: boolean }[] = [
  { id: "gemini-3.5-flash", thinking: true },
  { id: "gemini-3.5-flash-lite", thinking: false },
  { id: "gemini-3.8-flash", thinking: true },
];

const SYSTEM = `You are Saga, an investigation assistant. You explain counts and raw rows that were already taken from the merged log. You do not detect attacks, assign phases, score risk, or add events.
Rules:
- The counts are already computed. Repeat them when asked. Do not replace them with a new tally.
- Use only the evidence pack and the conversation.
- If a real question is not covered by the pack, say you cannot tell from this log. Do not guess, and do not invent hosts, addresses, users, files, times, or stages.
- If the message is nonsense, small talk, or not about this log, say so in one plain sentence and ask what they want to know about the counted rows. Do not quote these rules. Do not say "the pack" or "do not guess".
- Do not claim the other scenarios have been counted. This file is russellmitchell only.
- Keep the answer short. Use markdown when it makes the answer easier to read. Use LaTeX, with $...$ or $$...$$, only when a formula is needed.`;

type Turn = { role: "user" | "assistant"; text: string };

export type AskSagaResult = { ok: true; text: string } | { ok: false; error: string };

function readApiKey(): string | undefined {
  const fromEnv = process.env.GEMINI_API_KEY?.trim();
  if (fromEnv) return fromEnv;
  try {
    const file = readFileSync(join(process.cwd(), ".env"), "utf8");
    const line = file.split("\n").find((entry) => entry.startsWith("GEMINI_API_KEY="));
    const value = line?.slice("GEMINI_API_KEY=".length).trim().replace(/^["']|["']$/g, "");
    return value || undefined;
  } catch {
    return undefined;
  }
}

type GeminiPayload = {
  candidates?: Array<{ content?: { parts?: Array<{ text?: string; thought?: boolean }> } }>;
  error?: { message?: string };
};

async function generate(
  model: string,
  messages: Turn[],
  key: string,
  thinking: boolean,
  stream: boolean,
): Promise<Response> {
  const generationConfig: Record<string, unknown> = { maxOutputTokens: 500, temperature: 0.2 };
  if (thinking) generationConfig.thinkingConfig = { thinkingBudget: 0 };
  const method = stream ? "streamGenerateContent?alt=sse" : "generateContent";
  return fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:${method}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-goog-api-key": key },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: `${SYSTEM}\n\nEvidence pack:\n${evidencePack()}` }] },
      contents: messages.map((message) => ({
        role: message.role === "assistant" ? "model" : "user",
        parts: [{ text: message.text }],
      })),
      generationConfig,
    }),
  });
}

function partText(payload: GeminiPayload): string {
  const parts = payload.candidates?.[0]?.content?.parts ?? [];
  return parts
    .filter((part) => part.text && !part.thought)
    .map((part) => part.text)
    .join("");
}

function replyText(payload: GeminiPayload): string {
  return partText(payload).trim();
}

async function complete(model: string, messages: Turn[], key: string, thinking: boolean): Promise<string | undefined> {
  let response: Response;
  try {
    response = await generate(model, messages, key, thinking, false);
  } catch {
    return undefined;
  }
  if (response.status === 400 && thinking) {
    try {
      response = await generate(model, messages, key, false, false);
    } catch {
      return undefined;
    }
  }
  if (!response.ok) return undefined;
  const payload = (await response.json()) as Parameters<typeof replyText>[0];
  return replyText(payload) || undefined;
}

export async function answer(messages: Turn[]): Promise<AskSagaResult> {
  const key = readApiKey();
  if (!key) return { ok: false, error: "GEMINI_API_KEY is not available to the server." };

  for (const model of MODELS) {
    const text = await complete(model.id, messages, key, model.thinking);
    if (text) return { ok: true, text };
  }

  return { ok: false, error: "The models are not operational." };
}

export type StreamEvent =
  | { type: "status"; text: string }
  | { type: "delta"; text: string }
  | { type: "error"; text: string };

async function openStream(model: string, messages: Turn[], key: string, thinking: boolean): Promise<Response | undefined> {
  let response: Response;
  try {
    response = await generate(model, messages, key, thinking, true);
  } catch {
    return undefined;
  }
  if (response.status === 400 && thinking) {
    await response.body?.cancel();
    try {
      response = await generate(model, messages, key, false, true);
    } catch {
      return undefined;
    }
  }
  if (!response.ok) {
    await response.body?.cancel();
    return undefined;
  }
  return response;
}

async function emitDeltas(response: Response, write: (event: StreamEvent) => void): Promise<boolean> {
  const reader = response.body?.getReader();
  if (!reader) return false;
  const decoder = new TextDecoder();
  let buffer = "";
  let accumulated = "";
  let any = false;
  const take = (raw: string) => {
    const text = partText(JSON.parse(raw) as GeminiPayload);
    if (!text) return;
    const delta = accumulated && text.startsWith(accumulated) ? text.slice(accumulated.length) : text;
    accumulated = accumulated && text.startsWith(accumulated) ? text : accumulated + text;
    if (!delta) return;
    any = true;
    write({ type: "delta", text: delta });
  };
  const consume = (block: string) => {
    const data = block
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .join("");
    if (!data || data === "[DONE]") return;
    try {
      take(data);
    } catch {
      // A partial or non-JSON line is skipped. Later chunks still render.
    }
  };
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
    let sep = buffer.indexOf("\n\n");
    while (sep !== -1) {
      consume(buffer.slice(0, sep));
      buffer = buffer.slice(sep + 2);
      sep = buffer.indexOf("\n\n");
    }
  }
  if (buffer.trim()) consume(buffer);
  return any;
}

export async function streamAnswer(messages: Turn[], write: (event: StreamEvent) => void): Promise<void> {
  const key = readApiKey();
  if (!key) {
    write({ type: "error", text: "GEMINI_API_KEY is not available to the server." });
    return;
  }

  let wroteText = false;
  const forward = (event: StreamEvent) => {
    if (event.type === "delta") wroteText = true;
    write(event);
  };
  for (const model of MODELS) {
    const response = await openStream(model.id, messages, key, model.thinking);
    if (!response) continue;
    try {
      await emitDeltas(response, forward);
    } catch {
      if (wroteText) {
        forward({ type: "error", text: "The reply stopped before it finished." });
        return;
      }
      continue;
    }
    if (wroteText) return;
  }

  write({ type: "error", text: "The models are not operational." });
}
