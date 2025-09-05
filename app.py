import streamlit as st
import requests
import hashlib
import stripe
import random
from bs4 import BeautifulSoup
from deep_translator import GoogleTranslator

# ==================== Config / Secrets ====================
VT_KEY      = st.secrets.get("VIRUSTOTAL_API_KEY", "")
GC_KEY      = st.secrets.get("GOOGLE_FACT_CHECK_API_KEY", "")
STRIPE_KEY  = st.secrets.get("STRIPE_SECRET_KEY", "")
NEWSAPI_KEY = st.secrets.get("NEWSAPI_KEY", "")  # reserved for future use
FIREBASE_API_KEY = st.secrets.get("FIREBASE_API_KEY", "")# ✅ IMPORTANT: keep this on its own line (do NOT chain with a return)
FIREBASE_DB_URL = st.secrets.get("FIREBASE_DB_URL", "")

stripe.api_key = STRIPE_KEY
st.set_page_config(page_title="VerifyShield AI", layout="wide")

# ==================== Firebase Email/Password Auth (REST) ====================
def fb_signup(email: str, password: str):
    if not FIREBASE_API_KEY:
        return None, "Missing FIREBASE_API_KEY in Streamlit Secrets."
    try:
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        r = requests.post(url, json=payload, timeout=15).json()
        if "error" in r:
            return None, r["error"]["message"]
        return r, None
    except Exception as e:
        return None, str(e)

def fb_signin(email: str, password: str):
    if not FIREBASE_API_KEY:
        return None, "Missing FIREBASE_API_KEY in Streamlit Secrets."
    try:
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        r = requests.post(url, json=payload, timeout=15).json()
        if "error" in r:
            return None, r["error"]["message"]
        return r, None
    except Exception as e:
        return None, str(e)

# ==================== Helpers ====================
def track_event(event_name: str) -> None:
    ...# ==================== Language Selector ====================
st.sidebar.markdown("🌐 **Language**")
LANGUAGE_OPTIONS = {
    "English": "en",
    "Spanish": "es",
    "French": "fr",
    "German": "de",
    "Chinese (Simplified)": "zh-CN",
    "Chinese (Traditional)": "zh-TW",
    "Japanese": "ja",
    "Korean": "ko",
    "Malay": "ms",
    "Arabic": "ar",
    "Hindi": "hi",
    "Russian": "ru",
    "Portuguese": "pt",
    "Italian": "it",
}
selected_lang_name = st.sidebar.selectbox("Choose language", list(LANGUAGE_OPTIONS.keys()))
TARGET_LANG = LANGUAGE_OPTIONS[selected_lang_name]


def t(text: str) -> str:
    """Translate text into selected target language. Returns original if target is English or on error."""
    try:
        if not text or TARGET_LANG == "en":
            return text
        return GoogleTranslator(source="auto", target=TARGET_LANG).translate(text)
    except Exception:
        return text


# ==================== Helpers ====================
def track_event(event_name: str) -> None:
    """Lightweight analytics file (best-effort)."""
    try:
        with open("analytics.log", "a") as f:
            f.write(f"{event_name},User:{st.session_state.get('user_id','-')}\n")
    except Exception:
        pass


def _clean_html_to_text(html: str):
    """Extract title and body text from raw HTML using BeautifulSoup."""
    soup = BeautifulSoup(html, "lxml")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    # Grab readable text blocks
    paragraphs = [p.get_text(" ", strip=True) for p in soup.find_all("p")]
    text = "\n".join(p for p in paragraphs if p)
    return title, text


def summarize_text(title: str, text: str, max_sentences: int = 5) -> str:
    """Very simple extractive summary: take the first N non-trivial sentences."""
    raw = text.replace("\n", " ")
    # naive sentence split
    sentences = [s.strip() for s in raw.split(".") if len(s.split()) > 5]
    bullets = sentences[:max_sentences]
    body = "\n- " + "\n- ".join(bullets) if bullets else "\n- (Not enough content to summarize.)"
    return f"**{title or 'Summary'}**{body}"


def summarize_from_url(url: str):
    """Fetch article from URL, clean, summarize, and translate if needed."""
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return None, f"Error: HTTP {r.status_code}"

        title, text = _clean_html_to_text(r.text)
        if not text.strip():
            return None, "No text extracted from this page."

        summary = summarize_text(title, text)

        # Translate final summary into chosen language if needed
        if TARGET_LANG != "en":
            try:
                summary = GoogleTranslator(source="auto", target=TARGET_LANG).translate(summary)
            except Exception:
                pass

        return summary, None
    except Exception as e:
        return None, str(e)


# ==================== Session seed ====================
if "user_id" not in st.session_state:
    st.session_state.user_id = hashlib.sha256(
        str(st.session_state.get("session_id", "guest")).encode()
    ).hexdigest()[:8]


# ==================== Sidebar Nav ====================
st.sidebar.title(t("Navigation"))
nav_labels = {
    "Home": t("Home"),
    "News Summarizer": t("News Summarizer"),
    "About": t("About"),
}
page = st.sidebar.radio(
    t("Go to"),
    [nav_labels["Home"], nav_labels["News Summarizer"], nav_labels["About"]],
    key="nav_top",
)
# ==================== Sidebar Account Box ====================
if "user" not in st.session_state:
    st.session_state.user = None

with st.sidebar.expander("👤 Account", expanded=True):
    if st.session_state.user:
        st.markdown(f"**Signed in:** {st.session_state.user.get('email', '')}")
        if st.button("Log out", use_container_width=True):
            st.session_state.user = None
            st.rerun()
    else:
        tab_login, tab_signup = st.tabs(["Sign in", "Sign up"])

        with tab_login:
            li_email = st.text_input("Email", key="li_email")
            li_pass = st.text_input("Password", type="password", key="li_pass")
            if st.button("Sign in", key="li_btn", use_container_width=True):
                if not li_email or not li_pass:
                    st.warning("Please enter email and password.")
                else:
                    data, err = fb_signin(li_email, li_pass)
                    if err:
                        st.error(f"Sign in failed: {err}")
                    else:
                        st.session_state.user = {
                            "email": data.get("email", li_email),
                            "idToken": data.get("idToken", ""),
                            "refreshToken": data.get("refreshToken", ""),
                            "localId": data.get("localId", ""),
                        }
                        st.success("Signed in!")
                        st.rerun()

        with tab_signup:
            su_email = st.text_input("Email", key="su_email")
            su_pass = st.text_input("Password (min 6 chars)", type="password", key="su_pass")
            if st.button("Create account", key="su_btn", use_container_width=True):
                if not su_email or not su_pass:
                    st.warning("Please enter email and password.")
                else:
                    data, err = fb_signup(su_email, su_pass)
                    if err:
                        st.error(f"Sign up failed: {err}")
                    else:
                        st.success("Account created! You can sign in now.")
# ==================== HOME (Email/Link/Virus) ====================
if page == nav_labels["Home"]:
    st.title(t("VerifyShield AI - Detect Real or Fake Content"))
    track_event("page_view_home")

    st.subheader(t("Submit Content to Verify"))
    content_type = st.selectbox(
        t("Type:"),
        ["Email Text", "Link/URL", "Platform/Link for Virus"],
        key="type_sel",
    )
    user_input = st.text_area(t("Paste here:"), key="user_text", height=150)

    if st.button(t("Verify Now"), key="verify_btn"):
        if user_input.strip():
            verdict = "Real"
            virus_verdict = "Safe"
            explanation = ""

            # URL/Platform -> VirusTotal
            if content_type in ["Link/URL", "Platform/Link for Virus"]:
                try:
                    if not VT_KEY:
                        raise RuntimeError("Missing VirusTotal key (add VIRUSTOTAL_API_KEY to Secrets)")
                    vt_url = (
                        "https://www.virustotal.com/vtapi/v2/url/report"
                        f"?apikey={VT_KEY}&resource={user_input.strip()}"
                    )
                    response = requests.get(vt_url, timeout=20).json()
                    if response.get("positives", 0) > 0:
                        verdict = "Fake"
                        virus_verdict = "Malicious"
                        explanation = f"Detected as malicious/phishing by {response.get('positives')} engines."
                    else:
                        explanation = "No threats or fakes detected."
                except Exception as e:
                    explanation = f"VirusTotal error: {e}"

            # Email -> simple heuristics (no external calls)
            elif content_type == "Email Text":
                text_lower = user_input.lower()
                suspicious_keywords = [
                    "password", "bank", "urgent", "verify", "gift card",
                    "account locked", "click here", "confirm immediately",
                ]
                if any(k in text_lower for k in suspicious_keywords):
                    verdict = "Fake"
                    explanation = "Suspicious email content detected."
                else:
                    explanation = "No obvious phishing keywords found."

            # Output
            if verdict == "Fake" or virus_verdict == "Malicious":
                st.error(t(f"Verdict: {verdict}. Virus Check: {virus_verdict}. {explanation}"))
            else:
                st.success(t(f"Verdict: {verdict}. Virus Check: {virus_verdict}. {explanation}"))
        else:
            st.warning(t("Please paste some content first."))

    # Daily engagement
    st.subheader(t("Daily Learning: Motivate & Teach"))
    tips = [
        "Tip: Check email sender domain – fake ones mimic real (e.g., bank.com vs bankk.com).",
        "Quiz: Is 'urgent action required' a phishing sign? (Yes – creates panic).",
        "Lesson: For links, hover to see URL; use VerifyShield to check viruses.",
        "Tip: News with no sources? Likely fake – verify with us!",
    ]
    st.write(t(random.choice(tips)))


# ==================== NEWS SUMMARIZER ====================
elif page == nav_labels["News Summarizer"]:
    st.title(t("📰 AI Chatbox for News Summarization"))
    st.subheader(t("Paste a news article link, and I'll give you a professional TL;DR summary."))

    url_input = st.text_input(t("Paste a news URL"), key="news_url", placeholder="https://example.com/article")

    if st.button(t("Summarize"), key="summarize_btn"):
        if not url_input.strip():
            st.warning(t("Please enter a URL first."))
        else:
            with st.spinner(t("Fetching and summarizing...")):
                summary, err = summarize_from_url(url_input.strip())
                if err:
                    st.error(t(f"Error: {err}"))
                else:
                    st.success(summary)
                    st.markdown(f"**{t('Source')}:** {url_input}")


# ==================== ABOUT ====================
elif page == nav_labels["About"]:
    st.title(t("About VerifyShield AI"))
    st.markdown("## " + t("Our Mission"))
    st.write(t(
        "In 2025, fake emails, phishing links, and misinformation flood inboxes and feeds. "
        "VerifyShield AI helps users detect if content is real or fake, while teaching identification "
        "skills through daily engagement. From spotting scam emails to summarizing news, we're your daily authenticity guardian."
    ))
    st.markdown("## " + t("Key Features"))
    st.markdown(t(
        "- **Verification Scans:** Submit emails/links/news; get 'real or fake' verdicts.\n"
        "- **Virus Detection:** Check links/platforms for malware.\n"
        "- **News Summarizer:** Paste a link and get a professional TL;DR.\n"
        "- **Daily Courses:** Engaging lessons/quizzes to teach spotting fakes/viruses.\n"
        "- **Gamification:** Streaks, badges, and challenges for daily habits.\n"
        "- **Freemium Model:** Free basics, premium for unlimited."
    ))
    st.markdown("## " + t("Contact Us"))
    st.write(t("Email: support@verifyshield.ai"))
    st.write(t("Follow on X: @VerifyShieldAI"))


# ==================== Footer ====================
st.markdown("---")
st.write(t("Share verifications on X! #VerifyShieldAI | © 2025 VerifyShield AI"))
