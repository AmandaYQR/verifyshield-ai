import streamlit as st
import requests
import hashlib
import stripe
import random
import time
from datetime import datetime
from bs4 import BeautifulSoup
from deep_translator import GoogleTranslator

# ==================== Secrets / Config ====================
VT_KEY             = st.secrets.get("VIRUSTOTAL_API_KEY", "")
GC_KEY             = st.secrets.get("GOOGLE_FACT_CHECK_API_KEY", "")
STRIPE_KEY         = st.secrets.get("STRIPE_SECRET_KEY", "")
NEWSAPI_KEY        = st.secrets.get("NEWSAPI_KEY", "")          # optional (not used in this file)
FIREBASE_API_KEY   = st.secrets.get("FIREBASE_API_KEY", "")     # REQUIRED for login
FIREBASE_DB_URL    = st.secrets.get("FIREBASE_DB_URL", "")      # REQUIRED for history
stripe.api_key = STRIPE_KEY

st.set_page_config(page_title="VerifyShield AI", layout="wide")

# ==================== Language Selector ====================
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
selected_lang_name = st.sidebar.selectbox("Choose language", list(LANGUAGE_OPTIONS.keys()), key="lang_sel")
TARGET_LANG = LANGUAGE_OPTIONS[selected_lang_name]

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
    title = soup.title.string.strip() if soup.title and soup.title.string else "Untitled"
    paragraphs = [p.get_text(" ", strip=True) for p in soup.find_all("p")]
    text = "\n".join(p for p in paragraphs if p)
    return title, text

def summarize_text(title: str, text: str, max_sentences: int = 5):
    """Very simple extractive summary: first N reasonably-long sentences."""
    # Split on period and keep sentences > 6 words
    raw = [s.strip() for s in text.replace("! ", ". ").replace("? ", ". ").split(".")]
    sentences = [s for s in raw if len(s.split()) > 6]
    summary_lines = sentences[:max_sentences] if sentences else [text[:220] + ("..." if len(text) > 220 else "")]
    body = "\n- " + "\n- ".join(summary_lines)
    return f"**{title}**\n{body}"

def summarize_from_url(url: str):
    """Fetch article from URL, clean, summarize, and translate into chosen language."""
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return None, None, f"Error: HTTP {r.status_code}"

        title, text = _clean_html_to_text(r.text)
        if not text.strip():
            return None, None, "No readable text extracted from this page."

        summary = summarize_text(title, text)

        # Translate final summary if needed
        if TARGET_LANG != "en":
            try:
                summary = GoogleTranslator(source="auto", target=TARGET_LANG).translate(summary)
            except Exception:
                pass

        return title, summary, None
    except Exception as e:
        return None, None, str(e)

# ==================== Firebase Auth (Email/Password via REST) ====================
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

# ==================== Firebase DB (per-user history) ====================
def db_save_summary(uid: str, id_token: str, url: str, title: str, summary: str):
    """
    Save one summary under /users/{uid}/summaries in RTDB.
    """
    if not FIREBASE_DB_URL:
        return False, "Missing FIREBASE_DB_URL"
    try:
        payload = {
            "url": url,
            "title": (title or "Untitled")[:160],
            "summary": summary,
            "ts": int(time.time())
        }
        endpoint = f"{FIREBASE_DB_URL}/users/{uid}/summaries.json?auth={id_token}"
        r = requests.post(endpoint, json=payload, timeout=15)
        if r.status_code >= 300:
            return False, f"DB save failed: {r.text}"
        return True, None
    except Exception as e:
        return False, str(e)

def db_list_summaries(uid: str, id_token: str, limit: int = 50):
    """
    Return a list of {key, title, url, summary, ts} sorted by newest first.
    """
    if not FIREBASE_DB_URL:
        return []
    try:
        endpoint = f"{FIREBASE_DB_URL}/users/{uid}/summaries.json?auth={id_token}"
        r = requests.get(endpoint, timeout=15)
        if r.status_code >= 300:
            return []
        data = r.json() or {}
        items = []
        for k, v in data.items():
            items.append({
                "key": k,
                "title": v.get("title") or "Untitled",
                "url": v.get("url") or "",
                "summary": v.get("summary") or "",
                "ts": v.get("ts") or 0,
            })
        items.sort(key=lambda x: x["ts"], reverse=True)
        return items[:limit]
    except Exception:
        return []

# ==================== Session init ====================
if "user_id" not in st.session_state:
    st.session_state.user_id = hashlib.sha256(
        str(st.session_state.get("session_id", "guest")).encode()
    ).hexdigest()[:8]

if "user" not in st.session_state:
    st.session_state.user = None

# ==================== Sidebar Account Box ====================
with st.sidebar.expander("👤 Account", expanded=True):
    if st.session_state.user:
        st.markdown(f"**{t('Signed in')}:** {st.session_state.user.get('email', '')}")
        if st.button(t("Log out"), use_container_width=True, key="logout_btn"):
            st.session_state.user = None
            st.rerun()
    else:
        tab_login, tab_signup = st.tabs([t("Sign in"), t("Sign up")])

        with tab_login:
            li_email = st.text_input(t("Email"), key="li_email")
            li_pass = st.text_input(t("Password"), type="password", key="li_pass")
            if st.button(t("Sign in"), key="li_btn", use_container_width=True):
                if not li_email or not li_pass:
                    st.warning(t("Please enter email and password."))
                else:
                    data, err = fb_signin(li_email, li_pass)
                    if err:
                        st.error(t(f"Sign in failed: {err}"))
                    else:
                        st.session_state.user = {
                            "email": data.get("email", li_email),
                            "idToken": data.get("idToken", ""),
                            "refreshToken": data.get("refreshToken", ""),
                            "localId": data.get("localId", ""),
                        }
                        st.success(t("Signed in!"))
                        st.rerun()

        with tab_signup:
            su_email = st.text_input(t("Email"), key="su_email")
            su_pass = st.text_input(t("Password (min 6 chars)"), type="password", key="su_pass")
            if st.button(t("Create account"), key="su_btn", use_container_width=True):
                if not su_email or not su_pass:
                    st.warning(t("Please enter email and password."))
                else:
                    data, err = fb_signup(su_email, su_pass)
                    if err:
                        st.error(t(f"Sign up failed: {err}"))
                    else:
                        st.success(t("Account created! You can sign in now."))

# ==================== Navigation ====================
st.sidebar.title(t("Navigation"))
nav_labels = {
    "Home": t("Home"),
    "News Summarizer": t("News Summarizer"),
    "History": t("History"),
    "About": t("About"),
}
page = st.sidebar.radio(t("Go to"), [nav_labels["Home"], nav_labels["News Summarizer"], nav_labels["History"], nav_labels["About"]], key="nav_top")

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
                title, summary, err = summarize_from_url(url_input.strip())
                if err:
                    st.error(t(f"Error: {err}"))
                else:
                    st.success(summary)
                    st.markdown(f"**{t('Source')}:** {url_input}")

                    # Save to user history if signed in
                    if st.session_state.user:
                        ok, save_err = db_save_summary(
                            uid=st.session_state.user["localId"],
                            id_token=st.session_state.user["idToken"],
                            url=url_input.strip(),
                            title=title or "News Summary",
                            summary=summary
                        )
                        if ok:
                            st.info(t("✅ Saved to your history"))
                        else:
                            st.warning(t(f"⚠️ Not saved: {save_err}"))
                    else:
                        st.caption(t("Sign in to save this to your history."))

# ==================== HISTORY ====================
elif page == nav_labels["History"]]:
    st.title(t("📜 Your History"))
    if not st.session_state.user:
        st.warning(t("Please sign in to view your history."))
    else:
        items = db_list_summaries(
            st.session_state.user["localId"],
            st.session_state.user["idToken"]
        )
        if not items:
            st.info(t("No history yet. Summarize an article to add your first item."))
        else:
            for it in items:
                ts_str = datetime.fromtimestamp(it["ts"]).strftime("%Y-%m-%d %H:%M:%S")
                st.markdown(f"### [{t(it['title'])}]({it['url']})")
                st.write(it["summary"])
                st.caption(f"🕒 {ts_str}")
                st.divider()

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
        "- **Verification Scans:** Submit emails/links; get 'real or fake' verdicts.\n"
        "- **Virus Detection:** Check links/platforms for malware.\n"
        "- **News Summarizer:** Paste a link and get a professional TL;DR.\n"
        "- **History:** Signed-in users automatically save and revisit past summaries.\n"
        "- **Daily Courses:** Tips and quizzes to build skills.\n"
        "- **Freemium Model:** Free basics, premium for unlimited."
    ))
    st.markdown("## " + t("Contact Us"))
    st.write(t("Email: support@verifyshield.ai"))
    st.write(t("Follow on X: @VerifyShieldAI"))

# ==================== Footer ====================
st.markdown("---")
st.write(t("Share verifications on X! #VerifyShieldAI | © 2025 VerifyShield AI"))
