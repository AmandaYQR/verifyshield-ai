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
NEWSAPI_KEY = st.secrets.get("NEWSAPI_KEY", "")  # For possible future use

# ==================== Firebase Auth (Email/Password) ====================
FIREBASE_API_KEY = st.secrets.get("FIREBASE_API_KEY", "")

# REST endpoints
_FB_SIGNUP = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
_FB_SIGNIN = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"

def _fb_signup(email: str, password: str) -> dict:
    """Create account in Firebase Auth."""
    payload = {"email": email, "password": password, "returnSecureToken": True}
    try:
        r = requests.post(_FB_SIGNUP, json=payload, timeout=20)
        return r.json()
    except Exception as e:
        return {"error": {"message": str(e)}}

def _fb_signin(email: str, password: str) -> dict:
    """Login to Firebase Auth."""
    payload = {"email": email, "password": password, "returnSecureToken": True}
    try:
        r = requests.post(_FB_SIGNIN, json=payload, timeout=20)
        return r.json()
    except Exception as e:
        return {"error": {"message": str(e)}}stripe.api_key = STRIPE_KEY
st.set_page_config(page_title="VerifyShield AI", layout="wide")
# ==================== Auth Gate (login/signup) ====================
if "user" not in st.session_state:
    st.session_state.user = None  # will store Firebase response dict on login

def _render_auth():
    st.title("🔐 Sign in to VerifyShield AI")

    tab_login, tab_signup = st.tabs(["Login", "Sign up"])

    with tab_login:
        lemail = st.text_input("Email", key="login_email")
        lpass  = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login", type="primary", key="login_btn"):
            if not FIREBASE_API_KEY:
                st.error("Missing FIREBASE_API_KEY in Streamlit secrets.")
            else:
                res = _fb_signin(lemail, lpass)
                if "idToken" in res:
                    # keep the minimum we need
                    st.session_state.user = {
                        "email": res.get("email", lemail),
                        "idToken": res.get("idToken"),
                        "refreshToken": res.get("refreshToken"),
                        "localId": res.get("localId"),
                    }
                    st.success(f"Welcome {st.session_state.user['email']} 👋")
                    st.rerun()
                else:
                    st.error(res.get("error", {}).get("message", "Login failed"))

    with tab_signup:
        semail = st.text_input("Email", key="signup_email")
        spass  = st.text_input("Password (6+ chars)", type="password", key="signup_pass")
        if st.button("Create account", key="signup_btn"):
            if not FIREBASE_API_KEY:
                st.error("Missing FIREBASE_API_KEY in Streamlit secrets.")
            else:
                res = _fb_signup(semail, spass)
                if "idToken" in res:
                    st.success("Account created. Please go to the Login tab to sign in.")
                else:
                    st.error(res.get("error", {}).get("message", "Signup failed"))

# If not logged in, show auth and stop rendering the rest of the app.
if not st.session_state.user:
    _render_auth()
    st.stop()# ==================== Language Selector ====================
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

# Sidebar account info / logout
with st.sidebar:
    st.markdown(f"**Signed in:** {st.session_state.user.get('email', '')}")
    if st.button("Log out"):
        st.session_state.user = None
        st.rerun()
        
def t(text: str) -> str:
    """Translate text into selected target language. Return original on error or English."""
    try:
        if not text or TARGET_LANG == "en":
            return text
        return GoogleTranslator(source="auto", target=TARGET_LANG).translate(text)
    except Exception:
        return text

# ==================== Helpers ====================
def track_event(event_name: str) -> None:
    try:
        with open("analytics.log", "a") as f:
            f.write(f"{event_name},User:{st.session_state.get('user_id','-')}\n")
    except Exception:
        pass

def _clean_html_to_text(html: str):
    """Extract title and body text from raw HTML using BeautifulSoup."""
    soup = BeautifulSoup(html, "lxml")
    title = soup.title.string if soup.title else ""
    # Grab readable text blocks
    paragraphs = [p.get_text(" ", strip=True) for p in soup.find_all("p")]
    text = "\n".join(paragraphs)
    return title, text

def summarize_text(title: str, text: str, max_sentences: int = 5):
    """Simple extractive summarizer (top N sentences)."""
    sentences = text.split(".")
    sentences = [s.strip() for s in sentences if len(s.split()) > 5]
    summary = sentences[:max_sentences]
    return f"**{title}**\n\n" + "\n- " + "\n- ".join(summary)

def summarize_from_url(url: str):
    """Fetch article from URL, clean, summarize, and translate into chosen language."""
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

# ==================== Sidebar Nav ====================
if "user_id" not in st.session_state:
    st.session_state.user_id = hashlib.sha256(
        str(st.session_state.get("session_id", "guest")).encode()
    ).hexdigest()[:8]

st.sidebar.title(t("Navigation"))
nav_labels = {
    "Home": t("Home"),
    "News Summarizer": t("News Summarizer"),
    "About": t("About"),
}
page = st.sidebar.radio(t("Go to"), [nav_labels["Home"], nav_labels["News Summarizer"], nav_labels["About"]], key="nav_top")

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
    user_input = st.text_area(t("Paste here:"), key="user_text")

    if st.button(t("Verify Now"), key="verify_btn"):
        if user_input:
            verdict = "Real"
            virus_verdict = "Safe"
            explanation = ""

            # URL/Platform -> VirusTotal
            if content_type in ["Link/URL", "Platform/Link for Virus"]:
                try:
                    if not VT_KEY:
                        raise RuntimeError("Missing VirusTotal key")
                    vt_url = (
                        "https://www.virustotal.com/vtapi/v2/url/report"
                        f"?apikey={VT_KEY}&resource={user_input}"
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

            # Email -> simple heuristics
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

    url_input = st.text_input(t("Paste a news URL"), key="news_url")

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
                    st.markdown(f"**Source:** {url_input}")

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
