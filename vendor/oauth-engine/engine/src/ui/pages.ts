/**
 * Branded loopback callback pages, Team J.
 *
 * The surface almost no OAuth library controls: the page the user lands on after
 * consent (SPEC §25). Five terminal states — connected, denied, mismatch, timeout,
 * error — each DESIGNED, never defaulted. The rule is that the user should not
 * perceive that they left VoiceOS: same typography, same corner radii, same motion.
 *
 * Final-quality bar (SPEC §25/§28):
 *  - THEME-AWARE. The host has a dark surface, but light mode is a hard requirement,
 *    not a later pass. Every colour is a token on :root (light) and re-defined under
 *    `@media (prefers-color-scheme: dark)`, so the card matches whatever machine it
 *    lands on. `color-scheme: light dark` is declared so form UI and scrollbars follow.
 *  - ACCESSIBLE. Reduced motion is honoured (the rise animation is dropped). Every
 *    interactive control is a real focusable element with a visible `:focus-visible`
 *    ring, keyboard-reachable, and body/ink contrast clears WCAG AA in both themes.
 *  - PLAIN. Each state says what happened, what it means, and offers ONE action —
 *    "Back to VoiceOS" — so no state is a dead end whose only escape is closing a tab.
 *  - NO RAW ERRORS. No `code`, no `state`, no token, no verifier, no stack trace ever
 *    reaches the page. `providerMessage` is the provider's own human sentence, the
 *    ONLY provider-supplied free string rendered, and it is escaped and clipped hard.
 *    `providerIcon` renders only if it is a data:image/ URI.
 *
 * Hard rules:
 *  - Fully self-contained. No network fetch of any kind. Both marks are inline data URIs.
 *  - "close this tab" really tries window.close() and, when the browser refuses
 *    (tabs the script did not open), swaps itself to the honest fallback shortcut
 *    instead of sitting there broken.
 *  - The action button is the ONLY thing that focuses the app. The engine never
 *    auto-focuses; the user decides when to go back.
 */

export type PageState = 'success' | 'denied' | 'mismatch' | 'timeout' | 'provider_error';

export interface PageOptions {
  /** Display name of the provider, e.g. "Slack". Escaped before rendering. */
  provider?: string;
  /** Provider's own error text. Escaped + clipped. Never our paraphrase. */
  providerMessage?: string;
  /** Provider brand mark. Rendered only when it is a data:image/ URI. */
  providerIcon?: string;
}

interface PageCopy {
  title: string;
  headline: string;
  body: string;
  glyph: string;
  tone: 'ok' | 'warn' | 'bad';
}

const COPY: Record<PageState, PageCopy> = {
  success: {
    title: 'Connected',
    headline: 'You&rsquo;re connected.',
    body: 'You&rsquo;re all set. VoiceOS picked this up in the background.',
    glyph: '&#10003;',
    tone: 'ok',
  },
  denied: {
    title: 'Not connected',
    headline: 'Nothing was connected.',
    body: 'You declined the request, so no access was granted. Say &ldquo;connect&rdquo; again whenever you want to retry.',
    glyph: '&#215;',
    tone: 'warn',
  },
  mismatch: {
    title: 'Request rejected',
    headline: 'That response didn&rsquo;t match.',
    body: 'The reply didn&rsquo;t match the request VoiceOS started, so it was rejected and nothing was connected. Start the connection again from VoiceOS.',
    glyph: '&#33;',
    tone: 'bad',
  },
  provider_error: {
    title: 'Turned down',
    headline: 'That request was turned down.',
    body: 'The provider declined it, so nothing was connected. Its own words are below. VoiceOS will say what to do next.',
    glyph: '&#33;',
    tone: 'bad',
  },
  timeout: {
    title: 'Timed out',
    headline: 'That took too long.',
    body: 'VoiceOS stopped waiting for this approval. Nothing was connected. Say &ldquo;connect&rdquo; again to start a fresh request.',
    glyph: '&#8987;',
    tone: 'warn',
  },
};

/** Escape for HTML text context. Mandatory for anything provider-supplied. */
export function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Byte-budget clip so a hostile provider string can never blow up the page. */
export function clip(s: string, max = 200): string {
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}

/** The host app's own mark, extracted from VoiceOS.app at build time. Self-contained. */
const VOICEOS_MARK = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAeGVYSWZNTQAqAAAACAAEARoABQAAAAEAAAA+ARsABQAAAAEAAABGASgAAwAAAAEAAgAAh2kABAAAAAEAAABOAAAAAAAAAJAAAAABAAAAkAAAAAEAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAgKADAAQAAAABAAAAgAAAAACaA7zWAAAACXBIWXMAABYlAAAWJQFJUiTwAAACnmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNi4wLjAiPgogICA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgICAgICAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgICAgICAgICAgeG1sbnM6ZXhpZj0iaHR0cDovL25zLmFkb2JlLmNvbS9leGlmLzEuMC8iPgogICAgICAgICA8dGlmZjpYUmVzb2x1dGlvbj4xNDQ8L3RpZmY6WFJlc29sdXRpb24+CiAgICAgICAgIDx0aWZmOllSZXNvbHV0aW9uPjE0NDwvdGlmZjpZUmVzb2x1dGlvbj4KICAgICAgICAgPHRpZmY6UmVzb2x1dGlvblVuaXQ+MjwvdGlmZjpSZXNvbHV0aW9uVW5pdD4KICAgICAgICAgPGV4aWY6UGl4ZWxZRGltZW5zaW9uPjEwMjQ8L2V4aWY6UGl4ZWxZRGltZW5zaW9uPgogICAgICAgICA8ZXhpZjpQaXhlbFhEaW1lbnNpb24+MTAyNDwvZXhpZjpQaXhlbFhEaW1lbnNpb24+CiAgICAgICAgIDxleGlmOkNvbG9yU3BhY2U+MTwvZXhpZjpDb2xvclNwYWNlPgogICAgICA8L3JkZjpEZXNjcmlwdGlvbj4KICAgPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KOImb9AAAHGRJREFUeAHtnWusXcV1x7evn9zrBzYBG5sUgs0zPOxgoCIQDCRAgAKCUtQotBIiUiWqfqqEVKlSVfWhfmioSqp+AAnU5kMBJZRSoHwhTqApFCjiIZ4GUtu8wYBtjAE/+v+tmbX3nHP3OWfv87j3utnjO2dea9Zas9aamTWz9znOsiY0Emgk0EigkUAjgUYCjQQaCTQSaCTQSKCRQCOBRgKNBBoJ/FpIYNZMGeX+/fsnxMtCxUWKSxQPjmXqifMVxxUXKM4YvsVLGvarsFvxU8UvYrozpp8oJW5X3DFr1qxdSqc9TIsgpWyU+3XF9YonKh6j+BuK1B+kiJLHFP8/BYzjM0UU/7Him4ovKz6r+IziCzKKbUqnNEyZAUjpqzWyqxXPUlyniMKbUEgAg3hC8RHF+2QMrxZNo8uN3ACk+NPF/o2KVygyw5vQWwJsE/cr/q0M4ane4P1DjMwApPhVYusvFH9Xkf27CfUlwHbxT4p/JUPYUr977x4jMQAp/xqR/hvFr/VmoYGoIIGtgvkTGcE/V4CtBTJUA5DiDxH1Hyr+Xi0uGuCqErhVgH8sQ2CLGEoYmgFI+YeKo39VxMlrwugksFGovy8jwGkcOAzFAKT8w8TJTxW/OTBHDYIqEnhaQFfKCDZXAe4GM7ABNMrvJt6RtnFkvFhGMNDdwUCXLXHPv0eMNDN/pLouRc7x+i7pgJvTvsNABiCqf6fY7Pl9i3/gjhcIww9lBH2v5H13FFFu9e5SHNSIBpZCgyC7XlvB7f3IoS8DkPJXitgvFY/sh2jTZ+gSeFcYz5IRvF4Xc78GcIcI/b4Tk0GELNhi1tta004ARX2Ra+05qdQTsAOAVRdtRW4ShT4qOmPrpwUG6EcoE6sUHhrD57+ozK1rrdCCoUpPKfs0wf2n4nxjypVfpXMDM3QJJEbAY+f1KvOEsXLoZ//+I2EPd/uN8isLelSA+eob3qX4w7p0aq0AIvY1EeASYknQfdnCVJeFBn4YEogrwXvCdary71TFWXcF4CHPkoC8UX5VIU8hHDeyV9ahV9cAmgufOtKdQthkK7hC+cor+5yqPAopM583eTKI8S8zOmElwCF1lwDq6frA8uQMBrgAUfSJZeuXtk3CJLd4v3nGYYzKRxBnJcUUABN8ME9lZHSW8jYOVc0SAssbBHlCwO+0DF/4CDiSfmGMRR/LRabyMYv3iFjNga+QhLzBeX1AlcPlOAoE1uZcxy2AXtwQLlestA3UWQFOEtJVimEQJqFCza58bza4+OHKt7akX9En4Gn5TOAKXKrkL2kjnxSjeKympcH6UF0QFWwBl+cBsfrQltIK1ap3HGStkirgiz5pvzwfmuNwYsGSop/hphibPZPjiL1D4tSdvtXySH5tC1iXQh0D4AVOgy/IdsHcNE2nBM6sSryOAfAWb7T0qugbuKmUQLLS8qZ1pVDHANZUwtgAzQQJHC1jmF2FkUoGIGQTQmavcSdWVgV/AzOFEkh0g692cBXSlQxAiPjGToIw8QJyJ0aZPJ+7LtFfam2DMQN1T4eCvJzC0QmtNBslGizGcks/6kL/iCD0MRq0WGueWNEIhbbQFwQKTscwxDEamD4CeMRGW2ynW14CLm1xnAYUPsBDLuEhlK2SbAyOPxA2cGtxGirktAQb8cbOi5XG+5pY0yGpegzkpQO+sWMhEHMGVZUThzlAQoV/Onza1g5FmX7FQEJv+sSctRfloraoAyTUO3deAnuCKMlHyARdAedYks6CK0DT9qTeYAqovMWqrDGwk4OETGjOK43hoiRaRUEoC75DNZ8cJy1wVY8R9AxVVwCsyQwgWWZ6Im8AplYCiW6Y2MmK3ZmPqgYAsty8OqNrWmaQBJZV4aWqAeADNOHAkkAlnVU1AE4BTTgAJJBsA+NV2K1lAI4cd6Nwf1Tij0rqQzEUKMccqUdvTMvW34Fb+hWU0n6lefVPULTmaUsak2wOB6VO/EMvbaN/ezSYpN7KAipoBfzUe++iLdbEikn1oRMcttAtMEWAIqlkAFVPAfmXO90IAmFnM6S5gFX0Fmew4Ku1LW23PknHIhsG3QlHAScIFdJymjdaSUWSTfqoNvzl5FK49rYcKJBOiwXOFnypEQBeMrZIsIVuC/6ipci1jlvglXRbawWA3SYcMBKYW4XTqgaQrwBVkDYw0yiBYkkY3lWwhtMcAadRp3VIF/qvprNK+4QzkO7/XjdICr7wKsQgWIbbN3mxogUx/k368gVwY2NjeiGlmBuMZ9++fRZbOieFFD6pHmIWEyh46oW4lgGALChNBPSH+2Jv0hi9mDeKKDYwYRZJ1gSoJL4VgyDmzp2b7d27F6Sxl9KQtfIoP6A/e/Yc0d9jCnPFuJGbXpO3hOBlbPZsU/rnn3+ebdu2Lfvoo23Z9u07si+++MLGsnDhwuyQQw7Jli1bli1YsMDw7tmj8SGnaCiOH3z2RlJ8w4m3q5BNkJrLLspR8kEs4DBDVLPJXtAuOcMV5QjuqqG2AYDY2ImKmpSPlAPLecEy1kUfDOTLL7/MHnjggezFF18MRhBBpypBEatWrcouueQSUxgzl1AoilIYpBvqG2+8kT3xxBPZSy+9lH344YfZrl27sj17CgOi7/j4uBnBcccdl5122mnZMcccY4YGHMHxk3fZBSr6DH/WQjshlaMbj+u5pS3yGnpV/+zLAKqjL4ecrZl07733Zvfcc0+2e/dum0HlkKOrReGsPq+99lp20003ZXPnzYv6LmYrSzxCf/rpp7NHHnkke+GFF7KdO3dmn332maUYAIbsigH+oIMOstn//PPPZw899FB26qmnZuedd1528sknyxBmG02MwFbIMNFHN8gKmKfcABg8QnzqqacsffbZZ02I6cyowPdQQJYuXZo988wz2dYtW7PVa1Zne/exXAetMOs//vjj7K677sqefPJJU/r777+fvf3221bPso8RufJhiDFgBPRlOwD/Rx99ZP1ZDb73ve9lhx9+uK0attzbS6MyhWk0hCk3AJYtVzZ7KbOQVWCqA0qCjzlz5li6f19cf6WMOWr71a9+ld1+++3Zm2++mX3wwQfZ66+/bvu+z3gfg6fOP0bBeBjbJ598Yn1WrFiRPfroo4brxhtvzFavXm1Gj62hfLYAWxEcyRSmVe8BhsYSgp6YmMhOOeUUWy4PO+wwmzHuUSPQUUbozNFSvGjRouzggw/O1qxZky1fsTzbI2cQ48QgNr36avajH/3IZvvmzZttlWD2s4/DGzi6BR8Lxs0qgu/w1ltvZZs2bcpuvvnm7OWXX7Yxs3rYCoLt+cbeDfEI2rqPpISg8YnJEgmeeiYdiLUVrooPEsFs2LAh++pXv2pL4pIlS0yoCM6FN2wjKHCPZQu0T+Otf+UrX8muuuoq7dnzTQHs0SjqtttuM8W98sorGZEZ7fz4FlGUgxj4bK+jTGC7ePfdd20FYGW55ZZbZGSbzCfIjUBwng8izQUbZEwxjSAmpGCp7ENrz8/aBgDF/J8I2j9SMWIDgCcre5tVWJ1zgwEsX748u+yyy2yvXLlypTlOrqRhG0GKd+7cOTbzWQHOOeccW4m+/DLMbBR15513mvJxDlEWS37Kz9hY6wqV4nYDIPU+njJmjo7vvfee4b31tluNDjJxebl8VMFfXh8lWcidXIuMQ9n6JwaR4+uS6cMAumCr2MS8QNhnnXVWxnGJczMOEzMQgZF6PhVq3bzjIvU8xzSWfo6AGCCCJOATbPz5xuxVLf/vvPNOtnXrVnPyvG9d2u3w4ME/YEvAN+Ao+eCDD7asAs6LMdTnB8ZSJ9QygHqoO7Ph1x3z58/PLr/8cvMJWBE4QrniXWFp2ZVRLQ3G5HhI5+moh/LxQS688MJs5crDzQmFBo7eL37+Cyv/bzLz6efK9Dyp5dtWA+DytrZVwOvxIzACjpAcLdka6JfP6GiQnaU33JZaBiAuh0odYZx00km2FC9evDhzhxCFtEcXYJW0vS9lnDuWffwNzuQXXHCBnLq9JnzaUAbHU7z+nZ9+miu4G73ZY4WRGZzodIJPjYPVb8fOHUZr48aN1scMIM7eYawEVRVV/xiIDQTfpiqNErjCkBjspZdemnFxgkEwM7ZvD7+Ems4KF4qnJUhNmdT7jCX1MqvN0mVLzQgu1dLPKgA9jAPFcx9AGW+fftSX0QdfNx6MoD6cNuWUH6/f/dlu8y8ef/xxW424N2B+sYQDAw2HdZyjSGsbgDHoFgDDknF9e6BHGCD74qGHHpqdeeaZJnxWAWaIn7dzJTA7+EtWoXYhucBIPSI0lMnMnxifyE7S7P/6iSeasoFh9nMsw+jYm/H4Oyk/pQ3e9jJ1SENo89CJJ5xCxskWwB3D2rVrw8WS9Qw4GGqKK0caM2rOZR/EQk29UNsAQN8y8EizCumg9skMMvPOP/88ux0ENzOSGzSMw+lR73Q9bcGE0lXhijcdUKeIb4EBEH9Lsx9fAAXQxpKNxw8tjADcLO0YutP0NKVXykMEcKU7vPNEGXoE6hg3F0bQX7dundELfV218GDgHT96NHfs5w19GYB39rQqE6Vw0hTCXLbsEHMI77jjjoybs881E3dLOARXgAs9TVNhu6A9pS+zGccPIzj//POz448/Xpc+e7OxaBwonutdAnf8NvvHypXvdA244ofz5zx5SneMEPpbtmwxY/Bxep+KJAYCG4oBDMIB85bZxpK/fv16e9r23HPPab9eln2gJ277JSAXjCsgTW3ey4hcaC5gTzn2sb9y14DnT990pWAW7tixI1eGGQAc6cYypRNmYqkJ9xx+4AWwsCI5b55u/2S7bQccRaHgdGkfdZh2A0gHiPC/+93v2ln8UN3SMSPZkxFIGunjQiLvgnKBehmB4vnjAF500UV234DCWYYdFsOjzvHgExittlWA9n6MwHlxep6Cz/nY/flu4wF+jcgUKB76hBljAAiGJZEHJVwQcTziuhavnHo3AJhO85RNqMzruBK4kPH0x8cPyk444QTDiaK9jTTvqyzKwACJBPM/NB1ZnYKxkVrTpA/aA7qAMwVwOtSltMlDy42AdvCDJ+Dr7yTQgUXQl4baBuDMlWIrq4QjBhWSMoiWOgR/8cUX27GQBpwknELoeqTe8+kW4AKmnVmP08feD775ekNnb2IAwBB4MDRnTngyiHNYnD609cgHLQwg0Ay9qn+6AVgq7eJ7IBASZjxG4BdgRs2MoFB+u9woE8DSHpCJBNNe3bVcywCMgNB52hVz2hh56sUaQgI3ThurwP33328PbJi5KIZAu0cnERRPKeyxCHViYqEd8Xgh40Qd+1LlB/ggQh79cgnF9e/8+QvM4Bx/moKdct1gilcnp+kpeDA4VgAM1fZ/4Xf4nA7j9QIsV5Sld+mV1jKAXsiG1Y7Cv/Wtb9mxkC0ABfkRrV0p0HShuvCY/Sz97P/4FAiZlcXhUj4xFk4d3AVMTIzL79hlsCkdk3lUfh0jcH7S1HkgxQCgz0sipO6LpPy15HNLaKkdqFDvKnggUvU6s3+zdCMofAFesmSWpHGOnuy1lOXAoXz6IlCe9h151JHmQ6SCJ+8Bwzj66KPNSDgtoJQUp+WFF+eQSNnz3dJ2uLwc+0NngVYc6qFfx7Cc92GkM3IFYGDMhm984xsZr4w999yzti1s103dPpZEi0CFKZEqF8ESedr3ne98J9u3t5j5qeLpTXDHkyeSXD5hPJw+WlaAttkfit2no9NKU+eTrYrH0nPnzbXVBwNgvKlDGLgb/eeMMwCcumTXyy668KLsVb2UMWvxrPyKGLHs4xWuNgNAgO5QcexjC0gFC+5UIa5kln7eUHr44Ye13SyxPt7mKTTJp6kVOnykdABx5XvKSkWeG8CFCxfJEMNRtAO6kVXXNgCUgyBHFXxeIRyW51VHrMq+efbZ2UYdC3GW3BcoMwCWU4yA276169aaIl3gpCnbTodx8FSQZxGPPfaYbR34AcVpIKw4wLkBKBNNj9ryYPTUFFIMrzACvl/AKoVvA93wMqrDgi/IF3ujX9WQ81e1g+BqGwAjrzB8oU5F3MYRg+rSnEKzRJ8tA+AtYvZcZjQPUdKZiZBRPEIlf+6552ZzdbSjL+WghBQr9AsGMDReD9uwYYOdPFJDczom3ETx3YSd0ivoF0YAn/B2xhln2CNwX6WMQ+PXecX4PF+S1pBjSW+rqmUA3QbdSqAb14Ls0ZzigibHQpRz33332SrAUzuUhnAkL5swc/QtH/b709afZk/7UuW7ElLFpDTIowQMhxc4eVtn8eJFejTN//aOrYRVwMfvqTWWfYgnXyWNNjOaPzGLc7pfFwzs+/gok/gsw9eproYcO6GoZQCdkIyqHoEhbJTDUskqwDdyuN/ngigNs8e0Aqj+2xKqy8WEbxaSQnbOA3/FFVdkm/Vw5jO9lzA+HvwO7+GGkJY9n6fCgU0SwJemrFLgmJhYlP3Otdeav4IhU++w1mGAj57G2YZ7xh4DUz4ZFE4Tjh3GwHGN/d6PVqRfqv6cs8/RmXqFrQ6ufE9TfJPyUWMogyPndd//vtFDMTiVfvzj20Ms3/PmhqOi5b3OU/FCO23tPGoYZrzXXXdddoROKensh6dhGcGk8XWpOCAMAMGgeJw7vHXyrAJ+DsdAeMWccz/etCu9qkB9xrJOg5vnET/4wQ8MJ84gyjRaWr5R6rz50RBc6ZPSwjidR/BgnODluwjQwcDGZhUPprroqVqTL33VoA2qtgHYElNKKLiGpU1lDKWAab4MNtZBm0e6rAYIj/2USODSaGLhhJbYMJM6KR9Sk8jZV7ToF/qinCOOOCK74YYbzKgoE50etF2xPstJvc6/RQy89z399NMNH4bKzAeHGWryYqkNpIw/b+jUFgfU2zlPEMVsXz6AEZokRWGMX/32JmaW5yeTjo0+/boCCjXg0i7eOsq+++6786MawuWJH8Juf28/NQQz3shIJ3IOj5KY+VdceaXh/tnPfmYOIjTmSdmzdSJxWB8n5X1y8OjLjJ+l2Y2zt0EO7LHHHmv8tyhf8I6jVT44na01aalLUwpWKV/LAFIBlmJv46ytWNqlu4UkXZiekgqC5YYQQ9i8ZXO27OCl+mLnGhMuwkToIXXLSnDUyIKD8e6TMlEe2wJv7vBNYV7h4tVuP46maDEabhWPPPLI7ORTTs6O/tpqrQz+reDiHYCUR/ItoZLgWnr0mGltsEmxlgEk/aYt64pBwEcddZQ5fMxKggvVBeppXWadhvfHOSQ4TV5S8S94cBpxTx7nb/GSxXZs5dkFBsSMpx1c+bIfFW74Y74uj8OCP6AMIFUMQkXAROpNmJJKmh9ISCgm4nY8tiKILvs9by8ftvwwbU0BjklrMfLF7SIoUDogwDlvQeeqVAiflh3KBzzWCfUNAAJhBHXoDB02VXiK3OupQxT9Cph+LkrDmVbQhhz0x57fHoC3Fz/oo+jKBy7lL8234+ir7AzX6FzVAHLUZBjXTAgmQDHU6bsJnfmsNgrw+4yymZ4gpIwz3EuJebtwJd0lvtbSMORpznlNRFUNoOUXHFwogRYDye2jC/mqcCmK9j4lQlNVSa0haeUzxUu+jOd2eu19Wmfw5Nb2mqj0Uga7e/rtmEK5A39JdWJmlR4vVjWAT8sZorZMkGXQVeHSvu192ssp7DDyNfBL6ImwTQqleh4GWzmODvyl1QUT4R26vG95pupF0Bfl3Ztal0Ahd6+Z9rTSClDVALqsANM+0IaBcgnsKq9ura1qAPzf9D0dnlbUTWk6JJA7nVlWadJWNYACWc1z5nQIYaQ00/22KqG8T56p2nMQOJu0vRBUdQI/EaL9si5u+5WrMRA2xxLwDtVgD259SZ/QmHx2RZLA2TmhCsK0T5e8o+pCf1KT9ykTRhdSedMkhHlLPjpmf7ICfFxAdM5VXQEwgN0J8s4Y21vygbc2dKgOQF0bEzxV4foVekKqNNuFfpemUlQ9K7sgTJuijvjFy6EaAD/ZsWsW15pNmNESsKtnfdNdTA7VAHaA0L9TP6Ml8GvNHPuEBfQVfmcnVnRKKk1pLSscKbZ2QtLUzwwJyAXwwC9eDHUFAPGrfPTlB9BxBoR0r5wB7NRioRfvXHvP0ttFMbwmPeEH9AxVTwEgeoYPDKD7HTtQVUIXt7ZK91KYajh7CTOgroarlI1YWY6hvLYbHm/rxTfvF8bwrGd6pXmPXoBqf1pxf3QyKoD3Auk1nF79y9p74+wN4XirQ3qP9rQcQ3lte99+yv5+pPo+VbV/HQN4UUjf5mWIA3kbqCqYAw0OnfDqmQJ7//BXABHYJsRP+mtNUGrCzJHAmH7aLtygZb9U5q2qnNVZAcC5kQ++hdOEmSWBOPth6iearJX3mbqa/DcR2ME3ZNJn4TNLFL9m3EjVLP9szQofKj5YRwJ1TgEQek0ngAfkbFw7NnvM3sPPfVpl4tcCjH5aX9zExtq8UaB5v1DZ0hQLZs4pXE4or4z34aED5+H8cYVV8QEtvtoeH00gOM/TFAsG4XA+j1oADU0+pLxfJBpA0w5CHkPalkIU/KoW2qJr31WpwqNw801ojEDhp0rDr15Gmr0S69ULKG2XAaxT+VG9ij3uv6SRtjf5qZUAPhm/aiLF87zmDKWv1OGg7hYAIY6DP+ZrUMmxow7NBnaIEuCLKNIJGO+tq3w61V4B6KRV4Aglj+vd/JX8vDvv6Ddh6iXAj2SNHzQOYU5ovykDsNvaOpzUXgFALkI8F7iJ5SexwDp0G9gBJYDs+V3DGP60H+XTty8DoKMI/ljJbRhAfjnkThMATRiNBLjz15LPV8/icfwWEfrHfon1tQU4MW0Fi5XnaHguDiFf3GzC6CTA/OKRvP9moooPKP62DILn/32FgQwAijKClUr+XXHdgWoECHZQQQwDh9joGDjW8tX3RPnPC/h8Kf/9jp0qNPS9BThuMcC145WK/83PqRyIPsGgykcWw8ABnrLAV75m694F+cYLH+76rx5U+dAaGt9aCZYJ352K3+Z788TmdICIBw8cuZn5OH4K9yteL+W/NzjmAZzAduJiiKPI1Yq3sgpwOQHjqm8HbcoVJGBbinn6/PD1uCv/79X1mmEpHzZGoh2tBtfLOfhLaX/FHv23rJ9/wf8Szl1B+P7qSIgymgM+BE+CScPkYcmP4QOlf6b6f/CKYaUj04WMYI2Y/HOll4nxRfxShv+aRr41jNpzGpaURoRHstEcAXl4n58lHsXzI1gx8Gz/XsW/lgxf9sphpiMzAGdSgzxR+T9QvEZxBfX8pAsRo0AIRH3kD1iAaQlthpIW6ZrvMtaQtKaNqk5/RyBA8algbeH5ZugSWq1JFczIkLckp2d8q80e3giJK9MG0kGyQd9R4erAL4pxpR6du0Agy/Ds71G8WbRf8spRpB3YHD4pCYvj4uUxrld6aEoFY0gNIjcMAZmgU+A+8igH5bLpBVX3gcS6ILJgOOAxlG1SdINJU/JEZnl05toZwIf6L0UU/x+CfbMdYBTlNtZHQWIyTin0cNWuVTxD8QTF1apbpUEvUrpAaa3H1Op/oATe1OXShvf2eWy7SfE5xf9RfGaqlC5aeZgWA8ipx4yUzvlmqeISxcUxT3mhIk87iBgFbz0UxqEf39Kv9HBD4mt2mJoCmsbA9/K5EiXl+xSfKvJFTfZzj9vJS+GVXt0WbBMaCTQSaCTQSKCRQCOBRgKNBBoJNBJoJNBIoJFAI4FGAo0EGgkMJoH/A3/St8d8b62yAAAAAElFTkSuQmCC';

const CSS = `
*{box-sizing:border-box}
html,body{height:100%}
:root{
  color-scheme:light dark;
  --bg:#F6F6F4; --grid:rgba(24,24,27,.035);
  --card:#FFFFFF; --card-border:rgba(24,24,27,.06);
  --card-shadow:0 1px 2px rgba(24,24,27,.04),0 24px 64px rgba(24,24,27,.10);
  --ink:#18181B; --ink-soft:#57575E; --ink-faint:#82828A;
  --tile:#FFFFFF; --tile-shadow:0 1px 3px rgba(24,24,27,.10),0 8px 24px rgba(24,24,27,.08);
  --seg:rgba(24,24,27,.16);
  --detail-bg:#F6F6F4; --detail-border:rgba(24,24,27,.07);
  --btn-bg:#18181B; --btn-ink:#FFFFFF; --btn-shadow:0 2px 8px rgba(24,24,27,.22);
  --focus:#3D63FF;
  --band-ok:linear-gradient(180deg,#F2ECF7 0%,#FDF7F0 62%,var(--card) 100%);
  --band-warn:linear-gradient(180deg,#FBF3E4 0%,#FFFAF1 62%,var(--card) 100%);
  --band-bad:linear-gradient(180deg,#FBE9E4 0%,#FFF6F2 62%,var(--card) 100%);
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0A0A0C; --grid:rgba(255,255,255,.04);
    --card:#161619; --card-border:rgba(255,255,255,.09);
    --card-shadow:0 1px 2px rgba(0,0,0,.5),0 24px 64px rgba(0,0,0,.6);
    --ink:#F4F4F5; --ink-soft:#B4B4BC; --ink-faint:#78787F;
    --tile:#FFFFFF; --tile-shadow:0 1px 3px rgba(0,0,0,.55),0 8px 24px rgba(0,0,0,.5);
    --seg:rgba(255,255,255,.18);
    --detail-bg:#0D0D0F; --detail-border:rgba(255,255,255,.1);
    --btn-bg:#FAFAFA; --btn-ink:#161619; --btn-shadow:0 2px 10px rgba(0,0,0,.55);
    --focus:#8AA0FF;
    --band-ok:linear-gradient(180deg,#17231F 0%,#14171A 62%,var(--card) 100%);
    --band-warn:linear-gradient(180deg,#241E11 0%,#1A1712 62%,var(--card) 100%);
    --band-bad:linear-gradient(180deg,#2A1613 0%,#1B1413 62%,var(--card) 100%);
  }
}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font:400 16px/1.55 ui-sans-serif,-apple-system,"SF Pro Text",Inter,system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;
  display:flex; align-items:center; justify-content:center; padding:24px;
  background-image:radial-gradient(var(--grid) 1px,transparent 1px);
  background-size:22px 22px;
}
.card{
  width:100%; max-width:460px; background:var(--card); border:1px solid var(--card-border);
  border-radius:16px; box-shadow:var(--card-shadow);
  overflow:hidden; text-align:center;
  animation:rise .38s cubic-bezier(.2,.7,.2,1) both;
}
@keyframes rise{from{opacity:0;transform:translateY(8px) scale(.985)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){.card{animation:none}.btn:active{transform:none}}
.band{padding:44px 32px 30px}
.tone-ok .band{background:var(--band-ok)}
.tone-warn .band{background:var(--band-warn)}
.tone-bad .band{background:var(--band-bad)}
.tiles{display:flex;align-items:center;justify-content:center;gap:14px}
.tile{
  width:72px;height:72px;border-radius:17px;background:var(--tile);
  box-shadow:var(--tile-shadow);
  display:flex;align-items:center;justify-content:center;
}
.tile img{width:48px;height:48px;display:block;border-radius:10px}
.tie{display:flex;align-items:center}
.tie .seg{width:22px;height:2px;background:var(--seg)}
.tie .dot{
  width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-size:14px;font-weight:700;color:#fff;background:#1E9E67;flex:none;
  box-shadow:0 2px 8px rgba(30,158,103,.4);
}
.glyph{
  width:56px;height:56px;margin:0 auto;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  font-size:26px;line-height:1;font-weight:600;color:#fff;
  box-shadow:0 2px 12px rgba(0,0,0,.28);
}
.tone-ok .glyph{background:#1E9E67}
.tone-warn .glyph{background:#B0740C}
.tone-bad .glyph{background:#D42B1E}
.body{padding:26px 36px 30px}
h1{margin:0 0 10px;font-size:22px;line-height:1.25;letter-spacing:-.015em;font-weight:650;color:var(--ink)}
p{margin:0;color:var(--ink-soft);font-size:15px}
.btn{
  display:inline-block;margin-top:24px;padding:13px 30px;border-radius:999px;
  background:var(--btn-bg);color:var(--btn-ink);font-size:15px;font-weight:600;
  text-decoration:none;letter-spacing:-.01em;box-shadow:var(--btn-shadow);
}
.btn:active{transform:translateY(1px)}
.close{
  display:inline-block;margin-top:14px;font-size:13px;color:var(--ink-soft);
  text-decoration:underline;text-underline-offset:3px;cursor:pointer;background:none;border:none;
  font-family:inherit;padding:2px 4px;
}
.close:hover{color:var(--ink)}
.btn:focus-visible{outline:2px solid var(--focus);outline-offset:3px}
.close:focus-visible{outline:2px solid var(--focus);outline-offset:2px;border-radius:6px}
.detail{
  margin:20px auto 0;max-width:360px;padding:11px 14px;background:var(--detail-bg);
  border:1px solid var(--detail-border);border-radius:9px;
  font:400 13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
  color:var(--ink-soft);text-align:left;word-break:break-word;
}
.mark{
  padding:15px 32px;border-top:1px solid var(--card-border);
  font-size:11.5px;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-faint);
}
.mark b{font-weight:650;color:var(--ink);letter-spacing:.04em}
.mark span{display:block;margin-top:3px;letter-spacing:0;text-transform:none;font-size:12px}
`;

/** The close control: really tries, then swaps to the honest shortcut when refused. */
const CLOSE_SCRIPT = `
function tryClose(el){
  window.close();
  setTimeout(function(){
    if(!window.closed){ el.textContent='press \\u2318W to close this tab'; el.style.textDecoration='none'; el.style.cursor='default'; }
  },250);
}
`;

/**
 * Render one callback page. Pure string in, string out, no I/O, easy to snapshot-test.
 */
export function renderPage(state: PageState, opts: PageOptions = {}): string {
  const c = COPY[state];
  const provider = opts.provider ? esc(clip(opts.provider, 40)) : '';
  const headline =
    provider && state === 'success'
      ? `${provider} is connected.`
      : provider && state === 'provider_error'
        ? `${provider} turned that down.`
        : c.headline;
  const detail = opts.providerMessage
    ? `<div class="detail">${esc(clip(opts.providerMessage))}</div>`
    : '';

  const providerIcon =
    opts.providerIcon && /^data:image\/(png|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(opts.providerIcon)
      ? opts.providerIcon
      : '';
  const hero =
    state === 'success' && providerIcon
      ? `<div class="tiles" aria-hidden="true">
    <div class="tile"><img alt="" src="${VOICEOS_MARK}"></div>
    <div class="tie"><span class="seg"></span><span class="dot">&#10003;</span><span class="seg"></span></div>
    <div class="tile"><img alt="" src="${providerIcon}"></div>
  </div>`
      : `<div class="glyph" aria-hidden="true">${c.glyph}</div>`;
  // Every state hands back to the app with ONE clear action, so no page is a dead end
  // whose only escape is closing a tab (SPEC §25). `state` is a fixed enum — safe to
  // interpolate. Close stays as the honest secondary for tabs the app can't refocus.
  const actionLabel = state === 'success' ? 'Open VoiceOS' : 'Back to VoiceOS';
  const action = `<a class="btn" href="voiceos://integrations/callback?status=${state}">${actionLabel}</a>
  <div><button class="close" type="button" onclick="tryClose(this)">close this tab</button></div>`;

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow">
<title>${c.title} &middot; VoiceOS</title>
<style>${CSS}</style>
<script>${CLOSE_SCRIPT}</script>
</head>
<body>
<main class="card tone-${c.tone}" role="status" aria-live="polite">
  <div class="band">${hero}</div>
  <div class="body">
    <h1>${headline}</h1>
    <p>${c.body}</p>
    ${detail}
    ${action}
  </div>
  <div class="mark"><b>VoiceOS</b> Connect<span>Connected on this Mac. Tokens never leave your device.</span></div>
</main>
</body></html>`;
}
