import { createFileRoute } from "@tanstack/react-router";
import { parseTurns } from "@/data/ask-saga";

export const Route = createFileRoute("/api/ask")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        let messages: ReturnType<typeof parseTurns>;
        try {
          messages = parseTurns(await request.json());
        } catch (error) {
          const message = error instanceof Error ? error.message : "Send a message list.";
          return Response.json({ ok: false, error: message }, { status: 400 });
        }

        const encoder = new TextEncoder();
        const stream = new ReadableStream({
          async start(controller) {
            const send = (event: unknown) => {
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
            };
            try {
              const { streamAnswer } = await import("../../data/ask-saga.server");
              await streamAnswer(messages, send);
            } catch {
              send({ type: "error", text: "The assistant request failed. No new analysis was added." });
            } finally {
              controller.close();
            }
          },
        });

        return new Response(stream, {
          headers: {
            "content-type": "text/event-stream; charset=utf-8",
            "cache-control": "no-cache, no-transform",
          },
        });
      },
    },
  },
});
