import { useEffect, useRef, useState } from "react";
import type { UIMessage } from "ai";
import {
  ArrowUp,
  ArrowUpRight,
  ChartNoAxesCombined,
  CircleHelp,
  Fingerprint,
  LockKeyhole,
  RotateCcw,
  ShieldCheck,
  Unplug,
  X,
} from "lucide-react";
import {
  Conversation,
  ConversationContent,
  ConversationScrollButton,
} from "@/components/ai-elements/conversation";
import { Message, MessageContent, MessageResponse } from "@/components/ai-elements/message";
import {
  PromptInput,
  PromptInputTextarea,
  PromptInputFooter,
  PromptInputSubmit,
} from "@/components/ai-elements/prompt-input";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogCancel,
  AlertDialogAction,
} from "@/components/ui/alert-dialog";
import sagaMark from "@/assets/saga-mark.svg";
import { parseTurns } from "@/data/ask-saga";

const storageKey = "saga-security-conversation-v1";

type AskEvent =
  | { type: "status"; text: string }
  | { type: "delta"; text: string }
  | { type: "error"; text: string };

function isAskEvent(value: unknown): value is AskEvent {
  if (typeof value !== "object" || value === null || !("type" in value)) return false;
  const event = value as { type?: unknown; text?: unknown };
  return (
    (event.type === "status" || event.type === "delta" || event.type === "error") &&
    typeof event.text === "string"
  );
}

async function readAskEvents(response: Response, onEvent: (event: AskEvent) => void) {
  if (!response.body) throw new Error("The assistant returned no stream.");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const consume = (block: string) => {
    const data = block
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .join("");
    if (!data) return;
    const parsed: unknown = JSON.parse(data);
    if (isAskEvent(parsed)) onEvent(parsed);
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
}
const suggestions = [
  { text: "Summarize the security posture", icon: ShieldCheck },
  { text: "What activity should I investigate first?", icon: Fingerprint },
  { text: "Explain unusual authentication patterns", icon: ChartNoAxesCombined },
];

function readHistory(): UIMessage[] {
  const parsed: unknown = JSON.parse(localStorage.getItem(storageKey) ?? "[]");
  if (!Array.isArray(parsed)) return [];
  return parsed.filter(
    (m): m is UIMessage =>
      typeof m === "object" &&
      m !== null &&
      typeof m.id === "string" &&
      (m.role === "user" || m.role === "assistant") &&
      Array.isArray(m.parts) &&
      m.parts.every(
        (p: unknown) =>
          typeof p === "object" &&
          p !== null &&
          "type" in p &&
          p.type === "text" &&
          "text" in p &&
          typeof p.text === "string",
      ),
  );
}

export function InvestigationAssistant() {
  const [messages, setMessages] = useState<UIMessage[]>([]);
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [clearOpen, setClearOpen] = useState(false);
  const [ready, setReady] = useState(false);
  const [pending, setPending] = useState(false);
  const [activity, setActivity] = useState<string | null>(null);
  const [streamingId, setStreamingId] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  useEffect(() => {
    try {
      setMessages(readHistory());
    } catch {
      setError("Saved conversation could not be restored. You can start a new investigation.");
    }
    setReady(true);
    textareaRef.current?.focus({ preventScroll: true });
  }, []);
  useEffect(() => {
    if (!ready) return;
    try {
      localStorage.setItem(storageKey, JSON.stringify(messages));
    } catch {
      setError("Browser storage is unavailable. This conversation will not be saved.");
    }
  }, [messages, ready]);
  const send = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || pending) return;
    const next: UIMessage[] = [
      ...messages,
      { id: crypto.randomUUID(), role: "user", parts: [{ type: "text", text: trimmed }] },
    ];
    setMessages(next);
    setInput("");
    setError(null);
    setPending(true);
    setActivity("Explaining the merged log counts…");
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    const assistantId = crypto.randomUUID();
    let started = false;
    const pendingTokens: string[] = [];
    let revealed = "";
    let frame: number | null = null;
    const reveal = (token: string) => {
      revealed += token;
      const text = revealed;
      if (!started) {
        started = true;
        setActivity(null);
        setStreamingId(assistantId);
        setMessages((previous) => [
          ...previous,
          { id: assistantId, role: "assistant", parts: [{ type: "text", text }] },
        ]);
        return;
      }
      setMessages((previous) =>
        previous.map((message) =>
          message.id === assistantId ? { ...message, parts: [{ type: "text", text }] } : message,
        ),
      );
    };
    const pump = () => {
      if (frame !== null) return;
      const step = () => {
        frame = null;
        if (controller.signal.aborted) return;
        const token = pendingTokens.shift();
        if (!token) return;
        reveal(token);
        if (pendingTokens.length) frame = window.setTimeout(step, 40);
      };
      frame = window.setTimeout(step, pendingTokens.length > 1 ? 40 : 0);
    };
    try {
      const messages = parseTurns({
        messages: next.flatMap((message) => {
          const textPart = message.parts.find((part) => part.type === "text");
          if (!textPart || textPart.type !== "text") return [];
          if (message.role !== "user" && message.role !== "assistant") return [];
          return [{ role: message.role, text: textPart.text }];
        }),
      });
      const response = await fetch("/api/ask", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ messages }),
        signal: controller.signal,
      });
      if (!response.ok || !response.headers.get("content-type")?.includes("text/event-stream")) {
        const payload = (await response.json().catch(() => null)) as { error?: string } | null;
        setError(payload?.error ?? "The assistant request failed. No new analysis was added.");
        return;
      }
      await readAskEvents(response, (event) => {
        if (controller.signal.aborted) return;
        if (event.type === "status") return;
        if (event.type === "error") {
          setError(event.text);
          return;
        }
        const parts = event.text.match(/\s*\S+\s*/g);
        pendingTokens.push(...(parts ?? [event.text]));
        pump();
      });
      await new Promise<void>((resolve) => {
        const wait = () => {
          if (controller.signal.aborted || (pendingTokens.length === 0 && frame === null)) resolve();
          else requestAnimationFrame(wait);
        };
        wait();
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      setError("The assistant request failed. No new analysis was added.");
    } finally {
      if (abortRef.current === controller) {
        setPending(false);
        setActivity(null);
        setStreamingId(null);
        textareaRef.current?.focus({ preventScroll: true });
      }
    }
  };
  return (
    <section
      className="panel assistant-panel focus-section"
      id="assistant"
      aria-label="AI investigation assistant"
    >
      <div className="panel-heading">
        <div className="flex items-center gap-2.5">
          <img src={sagaMark} className="h-5 w-5" alt="" />
          <h2>Investigation assistant</h2>
          <span className="rounded border border-primary/25 bg-primary/10 px-1.5 py-0.5 font-mono text-[9px] text-primary">
            AI
          </span>
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="Clear conversation"
          title="Clear conversation"
          disabled={!messages.length}
          onClick={() => setClearOpen(true)}
        >
          <RotateCcw className="size-3.5 text-muted-foreground" />
        </Button>
      </div>

      <Conversation className="min-h-0" aria-label="Investigation conversation">
        <ConversationContent className={messages.length ? "gap-5 p-5" : "gap-0 p-0"}>
          {!messages.length ? (
            <div className="assistant-empty">
              <div className="agent-emblem">
                <img src={sagaMark} alt="Saga assistant" />
              </div>
              <div className="text-center">
                <span className="kicker">Your investigation partner</span>
                <h3 className="mt-2 text-xl font-medium">Clarity in every signal.</h3>
                <p className="mx-auto mt-3 max-w-80 text-xs leading-6 text-muted-foreground">
                  Ask about activity, explore patterns, and understand what matters to your security
                  posture.
                </p>
              </div>
              <div className="assistant-suggestions">
                <span className="kicker mb-0.5">Start an investigation</span>
                {suggestions.map(({ text, icon: Icon }) => (
                  <Button
                    variant="suggestion"
                    key={text}
                    className="h-10 w-full px-3 text-left"
                    onClick={() => {
                      setInput(text);
                      textareaRef.current?.focus({ preventScroll: true });
                    }}
                  >
                    <span className="suggestion-icon">
                      <Icon className="size-3.5 text-primary" />
                      <span className="whitespace-normal">{text}</span>
                    </span>
                    <ArrowUpRight className="size-3 text-muted-foreground" />
                  </Button>
                ))}
              </div>
            </div>
          ) : (
            <>

              {messages.map((message) => (
                <Message key={message.id} from={message.role}>
                  <MessageContent>
                    {message.parts.map((part, i) =>
                      part.type === "text" ? (
                        <MessageResponse
                          key={i}
                          mode={message.id === streamingId ? "streaming" : "static"}
                          isAnimating={message.id === streamingId}
                        >
                          {part.text}
                        </MessageResponse>
                      ) : null,
                    )}
                  </MessageContent>
                </Message>
              ))}
              {activity && (
                <Message from="assistant">
                  <MessageContent>
                    <p className="text-sm text-muted-foreground">{activity}</p>
                  </MessageContent>
                </Message>
              )}
            </>
          )}
        </ConversationContent>
        <ConversationScrollButton />
      </Conversation>
      <div className="chat-composer">
        {error && (
          <div
            role="alert"
            className="mb-3 flex items-start gap-2 rounded-md border border-warning/25 bg-warning/5 p-3 text-[11px] leading-5 text-secondary-foreground"
          >
            <Unplug className="mt-0.5 size-3.5 shrink-0 text-warning" />
            <span>{error}</span>
            <Button
              variant="ghost"
              size="icon-xs"
              aria-label="Dismiss notice"
              onClick={() => setError(null)}
            >
              <X />
            </Button>
          </div>
        )}
        <PromptInput allowAttachments={false} maxFiles={0} onSubmit={({ text }) => send(text)}>
          <PromptInputTextarea
            aria-label="Ask Saga a security question"
            placeholder="Ask Saga about your security data..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            ref={textareaRef}
          />
          <PromptInputFooter>
            <PromptInputSubmit
              disabled={!input.trim() || !ready || pending}
              status={pending ? "submitted" : undefined}
              aria-label="Send question"
              title="Send question"
            >
              <ArrowUp className="size-4" />
            </PromptInputSubmit>
          </PromptInputFooter>
        </PromptInput>

      </div>
      <AlertDialog open={clearOpen} onOpenChange={setClearOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Clear this investigation?</AlertDialogTitle>
            <AlertDialogDescription>
              Your saved conversation will be removed from this browser.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep conversation</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                abortRef.current?.abort();
                setMessages([]);
                setError(null);
                setActivity(null);
                setStreamingId(null);
                setPending(false);
                setTimeout(() => textareaRef.current?.focus({ preventScroll: true }), 0);
              }}
            >
              Clear conversation
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
