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

const storageKey = "saga-security-conversation-v1";
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
  const textareaRef = useRef<HTMLTextAreaElement>(null);
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
  const send = (text: string) => {
    if (!text.trim()) return;
    setMessages((previous) => [
      ...previous,
      { id: crypto.randomUUID(), role: "user", parts: [{ type: "text", text: text.trim() }] },
    ]);
    setInput("");
    setError(
      "The investigation service is not connected yet. Your question has been saved; no analysis has been performed.",
    );
    textareaRef.current?.focus({ preventScroll: true });
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
      <div className="flex items-center justify-between border-b border-border bg-background/25 px-5 py-2.5 text-[10px]">
        <span className="flex items-center gap-2 text-muted-foreground">
          <span className="size-1.5 rounded-full bg-warning" />
          Awaiting dataset analysis
        </span>
        <span className="font-mono text-muted-foreground">SAGA / ASSISTANT</span>
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
              <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                <LockKeyhole className="size-3" />
                Investigation · Saved in this browser
              </div>
              {messages.map((message) => (
                <Message key={message.id} from={message.role}>
                  <MessageContent>
                    {message.parts.map((part, i) =>
                      part.type === "text" ? (
                        <MessageResponse key={i}>{part.text}</MessageResponse>
                      ) : null,
                    )}
                  </MessageContent>
                </Message>
              ))}
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
            placeholder="Ask Saga about your security data…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            ref={textareaRef}
          />
          <PromptInputFooter>
            <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <LockKeyhole className="size-3" />
              Private investigation
            </span>
            <PromptInputSubmit
              disabled={!input.trim() || !ready}
              aria-label="Send question"
              title="Send question"
            >
              <ArrowUp className="size-4" />
            </PromptInputSubmit>
          </PromptInputFooter>
        </PromptInput>
        <div className="mt-2.5 flex items-center justify-center gap-1.5 text-[9px] text-muted-foreground">
          <CircleHelp className="size-2.5" />
          AI service not connected · Verify AI responses against source data
        </div>
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
                setMessages([]);
                setError(null);
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
