import streamlit as st
import requests
import hashlib
import stripe
import random
from deep_translator import GoogleTranslator

# ==================== Config / Secrets ====================
VT_KEY      = st.secrets.get("VIRUSTOTAL_API_KEY", "")
GC_KEY      = st.secrets.get("GOOGLE_FACT_CHECK_API_KEY", "")
STRIPE_KEY  = st.secrets.get("STRIPE_SECRET_KEY", "")
NEWSAPI_KEY = st.secrets.get("NEWSAPI_KEY", "")  # Used to surface mainstream coverage

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
selected_lang_name = st.sidebar.selectbox("Choose language", list(LANGUAGE_OPTIONS.keys()))
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

def google_fact_check(query: str):
    """Query Google Fact Check Tools for a claim."""
    if not GC_KEY:
        return {"claims": None, "error": "missing_key"}
    try:
        url = (
            "https://factchecktools.googleapis.com/v1alpha1/claims:search"
            f"?query={requests.utils.quote(query)}&key={GC_KEY}"
        )
        return requests.get(url, timeout=20).json()
    except Exception as e:
        return {"claims": None, "error": str(e)}

def fetch_mainstream_articles(query: str):
    """
    Use NewsAPI to retrieve mainstream coverage that matches the claim.
    Returns ([(title, url, source)], error | None | 'missing_key').
    """
    if not NEWSAPI_KEY:
        return [], "missing_key"
    try:
        url = (
            "https://newsapi.org/v2/everything?"
            f"q={requests.utils.quote(query)}&language=en&sortBy=relevancy&pageSize=5&apiKey={NEWSAPI_KEY}"
        )
        res = requests.get(url, timeout=20).json()
        if res.get("status") == "ok":
            items = []
            for a in res.get("articles", []):
                title = a.get("title") or "Article"
                url_  = a.get("url") or ""
                source = a.get("source", {}).get("name", "")
                if url_:
                    items.append((title, url_, source))
            return items, None
        return [], res.get("message") or "newsapi_error"
    except Exception as e:
        return [], str(e)

def heuristic_flags(text: str):
    """Very simple rule-based suspicion signals."""
    text_lower = text.lower()
    flags = []
    if any(w in text_lower for w in ["miracle", "secret", "cure", "shocking", "exposed", "one weird trick"]):
        flags.append("Clickbait/sensational phrasing detected.")
    if any(w in text_lower for w in ["yesterday", "today"]) and any(w in text_lower for w in ["retire", "death", "break up"]):
        flags.append("Time-sensitive, extraordinary claim without context.")
    return flags

# ==================== Sidebar Nav ====================
if "user_id" not in st.session_state:
    st.session_state.user_id = hashlib.sha256(
        str(st.session_state.get("session_id", "guest")).encode()
    ).hexdigest()[:8]

st.sidebar.title(t("Navigation"))
nav_labels = {
    "Home": t("Home"),
    "News/Article Checker": t("News/Article Checker"),
    "About": t("About"),
}
page = st.sidebar.radio(t("Go to"), [nav_labels["Home"], nav_labels["News/Article Checker"], nav_labels["About"]], key="nav_top")

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

            # Email -> simple heuristics + optional link scan
            elif content_type == "Email Text":
                text_lower = user_input.lower()
                links = [w for w in user_input.split() if w.startswith(("http://", "https://"))]
                suspicious_keywords = [
                    "password", "bank", "urgent", "verify", "gift card",
                    "account locked", "click here", "confirm immediately",
                ]
                if any(k in text_lower for k in suspicious_keywords):
                    verdict = "Fake"
                    explanation = "Suspicious email content detected."
                else:
                    explanation = "No obvious phishing keywords found."

                if links and VT_KEY:
                    try:
                        vt_url = (
                            "https://www.virustotal.com/vtapi/v2/url/report"
                            f"?apikey={VT_KEY}&resource={links[0]}"
                        )
                        response = requests.get(vt_url, timeout=20).json()
                        if response.get("positives", 0) > 0:
                            verdict = "Fake"
                            virus_verdict = "Malicious"
                            explanation += f" Suspicious link flagged by {response.get('positives')} engines."
                        else:
                            explanation += " Email link appears safe."
                    except Exception as e:
                        explanation += f" Link scan error: {e}"

            # Output
            if verdict == "Fake" or virus_verdict == "Malicious":
                st.error(t(f"Verdict: {verdict}. Virus Check: {virus_verdict}. {explanation}"))
            else:
                st.success(t(f"Verdict: {verdict}. Virus Check: {virus_verdict}. {explanation}"))

            # Streak
            if "streak" not in st.session_state:
                st.session_state.streak = 0
            st.session_state.streak += 1
            st.info(t(f"Streak: {st.session_state.streak} verifications!"))
            track_event("verification_completed")
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
    if st.button(t("Complete Daily Challenge"), key="daily_btn"):
        st.success(t("Well done! Learned something new."))
        track_event("daily_challenge_completed")

# ==================== NEWS / ARTICLE CHECKER (AI Chatbox) ====================
elif page == nav_labels["News/Article Checker"]:
    st.title(t("📰 AI Chatbox for News Verification"))
    st.subheader(t("Checking news/article (real/fake)"))
    st.caption(t("Ask about a headline or claim. I’ll check fact-checks, flag suspicious wording/domains, and show credible sources."))

    # Input box directly under heading
    claim_text = st.text_area(t("👉 Type or paste a headline/claim here:"), key="claim_box")

    if st.button(t("🔍 Check now"), key="check_news_btn"):
        if not claim_text.strip():
            st.warning(t("Please enter a headline first."))
        else:
            track_event("news_check_submit")

            # 1) Heuristics
            flags = heuristic_flags(claim_text)

            # 2) Google Fact Check
            fc = google_fact_check(claim_text)
            claims = fc.get("claims")
            fc_error = fc.get("error")

            # 3) Surface mainstream coverage
            articles, news_err = fetch_mainstream_articles(claim_text)

            # Decide verdict
            has_fc_false = False
            if claims:
                # If any review labels it false/misleading, mark fake
                for c in claims:
                    rating = (c.get("claimReview", [{}])[0].get("textualRating") or "").lower()
                    if rating in {"false", "misleading"}:
                        has_fc_false = True
                        break

            if has_fc_false:
                verdict = "Fake"
            elif flags and not articles:
                verdict = "Suspicious"
            else:
                verdict = "Unclear"

            # Present results
            if verdict == "Fake":
                st.error(t("Verdict: Fake"))
            elif verdict == "Suspicious":
                st.warning(t("Verdict: Suspicious"))
            else:
                st.info(t("Verdict: Unclear"))

            if flags:
                st.write(t("Heuristic flags:"))
                st.markdown("\n".join([f"- {t(f)}" for f in flags]))

            if fc_error and fc_error != "missing_key":
                st.info(t(f"Fact-check look-up issue: {fc_error}"))
            elif fc_error == "missing_key":
                st.info(t("Tip: Add GOOGLE_FACT_CHECK_API_KEY in your Streamlit Secrets for deeper checks."))

            if claims:
                st.write(t("Fact-check references found:"))
                for c in claims[:3]:
                    review = c.get("claimReview", [{}])[0]
                    site = review.get("publisher", {}).get("name", "Fact-checker")
                    rating = review.get("textualRating", "Rating N/A")
                    url = review.get("url", "")
                    if url:
                        st.markdown(f"- **{t(site)}** — {t(rating)} · [{t('Read review')}]({url})")
                    else:
                        st.markdown(f"- **{t(site)}** — {t(rating)}")

            if articles:
                st.write(t("Credible coverage from mainstream news:"))
                for title, url, source in articles:
                    st.markdown(f"- [{t(title)}]({url}) — _{t(source)}_")
            else:
                if news_err == "missing_key":
                    st.info(t("Tip: Add NEWSAPI_KEY in Streamlit Secrets to surface mainstream links."))
                elif news_err:
                    st.info(t(f"Could not fetch mainstream sources (reason: {news_err})."))

# ==================== ABOUT ====================
elif page == nav_labels["About"]:
    st.title(t("About VerifyShield AI"))
    st.markdown("## " + t("Our Mission"))
    st.write(t(
        "In 2025, fake emails, phishing links, and misinformation flood inboxes and feeds. "
        "VerifyShield AI helps users detect if content is real or fake, while teaching identification "
        "skills through daily engagement. From spotting scam emails to verifying news, we're your daily authenticity guardian."
    ))
    st.markdown("## " + t("Key Features"))
    st.markdown(t(
        "- **Verification Scans:** Submit emails/links/news; get 'real or fake' verdicts.\n"
        "- **Virus Detection:** Check links/platforms for malware.\n"
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

