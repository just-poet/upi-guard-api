# UPI Guard browser extension

Extract the ZIP. In Chrome visit chrome://extensions; in Edge visit edge://extensions. Enable Developer mode, choose Load unpacked, and select this folder. Pin UPI Guard to the toolbar.

In the hosted UPI Guard website, open Settings → Create connection code. Open the extension toolbar popup, enter the one-time code and Connect. Every client needs a fresh code. No OpenAI/shared backend key is included in this extension.

Select a message and click the floating shield, use the right-click menu on text or a link, press Alt+Shift+G, or open the toolbar popup. Explicitly choose Check this page to submit a bounded page-text excerpt. The shield can be dragged and globally disabled from the popup. It appears on ordinary HTTP/HTTPS pages; Chrome/Edge settings, extension stores, browser PDFs and some protected pages restrict extensions. Reload existing tabs after installation.

Requested text/link data goes to your backend and OpenAI. No passive screen, clipboard, inbox or keystroke monitoring is performed. The service may read public linked text without cookies, sign-in or running scripts. Results are indicators, never proof of authenticity. Connection tokens stay in trusted extension storage, expire after 30 days, can be revoked in website Settings, and may need reconnecting after a free-hosting restart.
