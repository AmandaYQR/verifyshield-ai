import streamlit as st
import requests
import hashlib
import stripe
import random
from deep_translator import GoogleTranslator  # ✅ replaced googletrans

# ------------------ Config ------------------
VT_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")
GC_KEY = st.secrets.get("GOOGLE_FACT_CHECK_API_KEY", "")
STRIPE_KEY = st.secrets.get("STRIPE_SECRET_KEY", "")
stripe.api_key = STRIPE_KEY

st.set_page_config(page_title="VerifyShield AI", layout="wide")

# ------------------ Language Selector ------------------
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
    "Italian": "it"
    # 👉 you can add more here
}
selected_lang_name = st.sidebar.selectbox("Choose language", list(LANGUAGE_OPTIONS.keys()))
TARGET_LANG = LANGUAGE_OPTIONS[selected_lang_name]

def t(text: str) -> str:
    """Translate text into selected TARGET_LANG. 
    Returns original if English or on error."""
    try:
        if not text or TARGET_LANG == "en":
            return text
        return GoogleTranslator(source="auto", target=TARGET_LANG).translate(text)
    except Exception:
        return text

# ------------------ Sidebar Nav ------------------
st.sidebar.title(t("Navigation"))
page = st.sidebar.radio(t("Go to"), [t("Home"), t("About")], key="nav_top")

# ------------------ HOME ------------------
if page == t("Home"):
    st.title(t("VerifyShield AI - Detect Real or Fake Content"))

    if "user_id" not in st.session_state:
        st.session_state.user_id = hashlib.sha256(
            str(st.session_state.get("session_id", "guest")).encode()
        ).hexdigest()[:8]

    def track_event(event_name: str) -> None:
        try:
            with open("analytics.log", "a") as f:
                f.write(f"{event_name},User:{st.session_state.user_id}\n")
        except Exception:
            pass

    track_event("page_view")

    # -------- Verification UI --------
    st.subheader(t("Submit Content to Verify"))
    content_type = st.selectbox(
        t("Type:"), ["Email Text", "Link/URL", "News/Article", "Platform/Link for Virus"], key="type_sel"
    )
    user_input = st.text_area(t("Paste here:"), key="user_text")

    if st.button(t("Verify Now"), key="verify_btn"):
        if user_input:
            verdict = "Real"
            virus_verdict = "Safe"
            explanation = ""

            # ---- URLs / Platform links ----
            if content_type in ["Link/URL", "Platform/Link for Virus"]:
                try:
                    vt_url = f"https://www.virustotal.com/vtapi/v2/url/report?apikey={VT_KEY}&resource={user_input}"
                    response = requests.get(vt_url, timeout=20).json()
                    if response.get("positives", 0) > 0:
                        verdict = "Fake"
                        virus_verdict = "Malicious"
                        explanation = f"Detected as malicious/phishing by {response.get('positives')} engines."
                    else:
                        explanation = "No threats or fakes detected."
                except Exception as e:
                    explanation = f"VirusTotal error: {e}"

            # ---- News/Article ----
            elif content_type == "News/Article":
                try:
                    gc_url = f"https://factchecktools.googleapis.com/v1alpha1/claims:search?query={user_input}&key={GC_KEY}"
                    response = requests.get(gc_url, timeout=20).json()
                    if response.get("claims"):
                        claim = response["claims"][0]
                        rating = claim.get("claimReview", [{}])[0].get("textualRating", "").lower()
                        if rating in {"false", "misleading"}:
                            verdict = "Fake"
                        explanation = claim.get("claimReview", [{}])[0].get("reviewRating", {}).get(
                            "alternateName", "Fact-check info found."
                        )
                    else:
                        explanation = "No fact-check results found."
                except Exception as e:
                    explanation = f"Fact check error: {e}"

            # ---- Email Text ----
            elif content_type == "Email Text":
                text_lower = user_input.lower()
                links = [w for w in user_input.split() if w.startswith(("http://", "https://"))]
                suspicious_keywords = ["password", "bank", "urgent", "verify", "gift card", "account locked", "click here"]

                if any(k in text_lower for k in suspicious_keywords):
                    verdict = "Fake"
                    explanation = "Suspicious email content detected."
                else:
                    explanation = "No obvious phishing keywords found."

                if links:
                    try:
                        vt_url = f"https://www.virustotal.com/vtapi/v2/url/report?apikey={VT_KEY}&resource={links[0]}"
                        response = requests.get(vt_url, timeout=20).json()
                        if response.get("positives", 0) > 0:
                            verdict = "Fake"
                            virus_verdict = "Malicious"
                            explanation += f" Suspicious link flagged by {response.get('positives')} engines."
                        else:
                            explanation += " Email link appears safe."
                    except Exception as e:
                        explanation += f" Link scan error: {e}"

            # ---- Output results ----
            if verdict == "Fake" or virus_verdict == "Malicious":
                st.error(t(f"Verdict: {verdict}. Virus Check: {virus_verdict}. {explanation}"))
            else:
                st.success(t(f"Verdict: {verdict}. Virus Check: {virus_verdict}. {explanation}"))

            # Gamification
            if "streak" not in st.session_state:
                st.session_state.streak = 0
            st.session_state.streak += 1
            st.info(t(f"Streak: {st.session_state.streak} verifications!"))
            track_event("verification_completed")
        else:
            st.warning(t("Please paste some content first."))

    # -------- Daily Engagement --------
    st.subheader(t("Daily Learning: Motivate & Teach"))
    tips = [
        "Tip: Check email sender domain – fake ones mimic real (e.g., bank.com vs bankk.com).",
        "Quiz: Is 'urgent action required' a phishing sign? (Yes – creates panic).",
        "Lesson: For links, hover to see URL; use VerifyShield to check viruses.",
        "Tip: News with no sources? Likely fake – verify with us!"
    ]
    st.write(t(random.choice(tips)))
    if st.button(t("Complete Daily Challenge"), key="daily_btn"):
        st.success(t("Well done! Learned something new."))
        track_event("daily_challenge_completed")

# ------------------ ABOUT ------------------
elif page == t("About"):
    st.title(t("About VerifyShield AI"))
    st.markdown("## " + t("Our Mission"))
    st.write(t("In 2025, fake emails, phishing links, and misinformation flood inboxes and feeds. "
               "VerifyShield AI helps users detect if content is real or fake, while teaching identification "
               "skills through daily engagement. From spotting scam emails to verifying news, we're your daily authenticity guardian."))

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

st.markdown("---")
st.write(t("Share verifications on X! #VerifyShieldAI | © 2025 VerifyShield AI"))
