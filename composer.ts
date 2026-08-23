/**
 * COMPOSER (Phase D2, Path W) — the Slack-look confirmation composer widgets for
 * `slack_send_message` and `slack_thread_reply`.
 *
 * Frozen contract: docs/design/rehaul/COMPOSER-SPEC.md. Every construct in these documents is
 * cited in that spec's §4.1 table to a verified byte in DIALECT-VERIFIED.md or
 * WIDGET-BRIDGE-VERIFIED.md. The rules the HTML obeys:
 *
 *   - The bridge key is `text` — the REAL argument name in tools.ts for both tools — pushed
 *     through `parent.postMessage({type:'voiceos:updateInput', key:'text', value}, '*')` on
 *     every input event (W§Q1). Prefill arrives via `voiceos:init` `{args}` (W§Q1.5) and is
 *     injected with `textContent` only, so arg content can never break the DOM.
 *   - Exactly FOUR live toolbar buttons — B, I, strikethrough, code — the Slack mrkdwn wraps
 *     (`*` `_` `~` backtick) that round-trip through chat.postMessage. Every dead mockup
 *     control (link, lists, Aa, @, emoji, paperclip, send-arrow) is OMITTED, not disabled:
 *     present = functional; absent = honest.
 *   - No on-card Cancel or Send. Bottom-left is the muted "Say cancel to discard" hint (copy,
 *     not a control); the bottom-right ~150x44 zone stays clear for the host's floating glass
 *     confirm pill (W§Q2).
 *   - All art inline: the Slack pinwheel is a data: SVG <img> (W§Q3 — unrestricted inside the
 *     widget). Zero external references (the window CSP would block them anyway).
 */

import { COMPOSER_CHROME } from './copy.ts';

/**
 * The Slack pinwheel as a data: URI — the card icon on every Path-D confirmation card
 * (tools.ts imports it) and the widget header icon here. Lives in this module so tools.ts and
 * the widget builders share ONE constant without an import cycle. Risk class MEDIUM
 * (DESIGN-SPEC §6): if `validateManifest` or the renderer rejects the data URI, delete the
 * `icon` line in tools.ts `confirmCard` and nothing else changes.
 */
export const SLACK_ICON =
  "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 122.8 122.8'><path d='M25.8 77.6c0 7.1-5.8 12.9-12.9 12.9S0 84.7 0 77.6s5.8-12.9 12.9-12.9h12.9v12.9zm6.5 0c0-7.1 5.8-12.9 12.9-12.9s12.9 5.8 12.9 12.9v32.3c0 7.1-5.8 12.9-12.9 12.9s-12.9-5.8-12.9-12.9V77.6z' fill='%23E01E5A'/><path d='M45.2 25.8c-7.1 0-12.9-5.8-12.9-12.9S38.1 0 45.2 0s12.9 5.8 12.9 12.9v12.9H45.2zm0 6.5c7.1 0 12.9 5.8 12.9 12.9s-5.8 12.9-12.9 12.9H12.9C5.8 58.1 0 52.3 0 45.2s5.8-12.9 12.9-12.9h32.3z' fill='%2336C5F0'/><path d='M97 45.2c0-7.1 5.8-12.9 12.9-12.9s12.9 5.8 12.9 12.9-5.8 12.9-12.9 12.9H97V45.2zm-6.5 0c0 7.1-5.8 12.9-12.9 12.9s-12.9-5.8-12.9-12.9V12.9C64.7 5.8 70.5 0 77.6 0s12.9 5.8 12.9 12.9v32.3z' fill='%232EB67D'/><path d='M77.6 97c7.1 0 12.9 5.8 12.9 12.9s-5.8 12.9-12.9 12.9-12.9-5.8-12.9-12.9V97h12.9zm0-6.5c-7.1 0-12.9-5.8-12.9-12.9s5.8-12.9 12.9-12.9h32.3c7.1 0 12.9 5.8 12.9 12.9s-5.8 12.9-12.9 12.9H77.6z' fill='%23ECB22E'/></svg>";

/**
 * One skeleton, two documents. The send and reply composers differ ONLY in the header label,
 * the context rows under it, one optional CSS rule (the reply quote block), and the
 * `voiceos:init` handler body — COMPOSER-SPEC §1.4 declares everything else byte-identical,
 * so everything else IS one template.
 */
function composerDoc(opts: { header: string; contextRows: string; extraCss: string; initBody: string }): string {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
*{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
html,body{background:transparent}
.composer{background:#1A1D21;border:1px solid rgba(255,255,255,.09);border-radius:10px;overflow:hidden;color:#D1D2D3}
.hdr{display:flex;align-items:center;gap:9px;background:rgba(255,255,255,.07);border-bottom:1px solid rgba(255,255,255,.06);padding:11px 14px}
.hdr img{width:18px;height:18px}
.hdr b{font-size:14px;font-weight:700;color:#E8E8E8}
.row{display:flex;align-items:center;gap:10px;padding:12px 14px 0}
.lbl{font-size:13px;color:#9EA0A3}
.pill{display:inline-flex;align-items:center;gap:5px;background:rgba(29,155,209,.16);color:#6FB6E3;border-radius:5px;padding:3px 10px;font-size:13px;font-weight:600}
.hash{opacity:.75;font-weight:400}
.msgwrap{margin:12px 14px 0;border:1px solid rgba(255,255,255,.16);border-radius:9px;background:#222529}
.msgwrap:focus-within{border-color:rgba(29,155,209,.65)}
.bar{display:flex;gap:2px;border-bottom:1px solid rgba(255,255,255,.08);padding:5px 7px}
.bar button{border:0;background:transparent;border-radius:5px;width:29px;height:26px;color:#ABABAD;font-size:13px;cursor:pointer}
.bar button:hover{background:rgba(255,255,255,.09);color:#E8E8E8}
.bb{font-weight:800}.ii{font-style:italic;font-family:Georgia,serif}.ss{text-decoration:line-through}.cc{font-family:ui-monospace,Menlo,monospace;font-size:11px}
textarea{display:block;width:100%;border:0;outline:0;resize:none;overflow-y:auto;padding:10px 12px;font-size:14px;line-height:1.45;color:#E8E8E8;background:transparent;min-height:42px;max-height:200px}
textarea::placeholder{color:#7A7C7E}
.foot{height:12px}
${opts.extraCss}</style></head><body>
<div class="composer">
 <div class="hdr"><b>${opts.header}</b></div>
${opts.contextRows}
 <div class="msgwrap">
  <div class="bar">
   <button class="bb" data-w="*" type="button" aria-label="Bold">B</button>
   <button class="ii" data-w="_" type="button" aria-label="Italic">I</button>
   <button class="ss" data-w="~" type="button" aria-label="Strikethrough">S</button>
   <button class="cc" data-w="\`" type="button" aria-label="Code">&lt;/&gt;</button>
  </div>
  <textarea id="msg" rows="2"></textarea></div>
 <div class="foot"></div>
</div>
<script>
var msg=document.getElementById('msg');
function push(){parent.postMessage({type:'voiceos:updateInput',key:'text',value:msg.value},'*');}
function fit(){msg.style.height='auto';msg.style.height=Math.min(msg.scrollHeight,200)+'px';
 var total=document.querySelector('.composer').offsetHeight+52;
 parent.postMessage({type:'voiceos:resize',height:Math.max(60,Math.min(420,total))},'*');}
msg.addEventListener('input',function(){push();fit();});
window.addEventListener('message',function(e){var d=e.data||{};
${opts.initBody}
 if(d.type==='voiceos:init'){fit();}});
setTimeout(fit,0);
Array.prototype.forEach.call(document.querySelectorAll('.bar button'),function(b){
 b.addEventListener('click',function(){var w=b.getAttribute('data-w');
  var s=msg.selectionStart,e2=msg.selectionEnd,v=msg.value;
  msg.value=v.slice(0,s)+w+v.slice(s,e2)+w+v.slice(e2);
  msg.focus();msg.setSelectionRange(s+1,e2+1);push();});});
</script></body></html>`;
}

/**
 * The send composer (COMPOSER-SPEC §1.3): "New message" header, To: line + channel chip
 * (WITHOUT the mockup's "x" — a remove control we cannot honor is a dead control), the
 * blue-outlined message box with the four live format buttons, the cancel hint.
 */
export function sendComposerHtml(): string {
  return composerDoc({
    header: COMPOSER_CHROME.new_message,
    contextRows:
      ` <div class="row"><div class="lbl">${COMPOSER_CHROME.to}</div>
  <span class="pill"><span class="hash" id="pillHash">#</span><span id="pillName"></span></span></div>`,
    extraCss: '',
    initBody:
      ` if(d.type==='voiceos:init'){var a=d.args||{};msg.value=String(a.text==null?'':a.text);
  var t=String(a.target==null?'':a.target);var h=t.charAt(0)==='#';
  document.getElementById('pillHash').style.display=h?'':'none';
  document.getElementById('pillName').textContent=h?t.slice(1):t;}`,
  });
}

/**
 * The reply composer (COMPOSER-SPEC §1.4): "Reply in thread" header, In + channel link, a
 * quoted original-message block hidden entirely when `replying_to` is empty; everything else
 * identical to send.
 */
export function replyComposerHtml(): string {
  return composerDoc({
    header: COMPOSER_CHROME.reply_in_thread,
    contextRows:
      ` <div class="row"><div class="lbl">${COMPOSER_CHROME.in}</div>
  <span class="pill"><span class="hash" id="chHash">#</span><span id="chName"></span></span></div>
 <div class="row" id="quoteRow" style="display:none"><div class="quote" id="quoteText"></div></div>`,
    extraCss:
      '.quote{border-left:3px solid rgba(255,255,255,.22);padding:4px 10px;color:#9EA0A3;font-size:13px;line-height:1.4;max-height:56px;overflow:hidden}\n',
    initBody:
      ` if(d.type==='voiceos:init'){var a=d.args||{};msg.value=String(a.text==null?'':a.text);
  var c=String(a.channel==null?'':a.channel);var ch=c.charAt(0)==='#';
  document.getElementById('chHash').style.display=ch?'':'none';
  document.getElementById('chName').textContent=ch?c.slice(1):c;
  var q=String(a.replying_to==null?'':a.replying_to);
  if(q){document.getElementById('quoteRow').style.display='';
   document.getElementById('quoteText').textContent=q;}}`,
  });
}
