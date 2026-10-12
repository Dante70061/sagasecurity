<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Dashboard architecture
- Keep Saga's dashboard at the index route with separate assistant, analytics, and findings modules, so presentation can evolve without introducing extra pages.
- Keep demonstration metrics in a browser-safe data module and mark every derived display as demo, so placeholders cannot be mistaken for analyzed results.
- Use AI Elements conversation, message and prompt primitives; keep the current assistant disconnected with browser-local message parts until an API is explicitly requested, so no fabricated AI or detection output is presented.
- Read render-visible browser storage after hydration and validate saved message shapes, so SSR remains consistent and corrupted history degrades safely.
