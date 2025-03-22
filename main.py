import os
import json
import requests
import json
from groq import Groq
import bcrypt
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import firebase_admin
from firebase_admin import credentials, auth, firestore
from dotenv import load_dotenv
from youtube_transcript_api import YouTubeTranscriptApi

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Initialize Firebase
cred_path = os.getenv("FIREBASE_CREDENTIALS")
if not cred_path:
    raise ValueError("FIREBASE_CREDENTIALS environment variable not set")

firebase_creds_dict = json.loads(cred_path)

cred = credentials.Certificate(firebase_creds_dict)
firebase_admin.initialize_app(cred)
# cred = credentials.Certificate(cred_path)
# firebase_admin.initialize_app(cred)
db = firestore.client()

# Groq API Key
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

def extract_video_id(video_url):
    """Extracts the video ID from the given YouTube URL."""
    if "youtube.com/watch?v=" in video_url:
        return video_url.split("v=")[-1].split("&")[0]
    elif "youtu.be/" in video_url:
        return video_url.split("youtu.be/")[-1].split("?")[0]
    return None

def get_youtube_transcript(video_url):
    """Fetches the transcript for the given YouTube video URL."""
    video_id = extract_video_id(video_url)
    if not video_id:
        return "Invalid YouTube URL"
    try:
        transcript_list = YouTubeTranscriptApi.get_transcript(video_id)
        transcript = " ".join([entry["text"] for entry in transcript_list])
        return transcript
    except Exception as e:
        return str(e)

def summarize_with_groq(text):
    """Sends the extracted transcript to Groq's API for summarization."""
    client = Groq(
    api_key=GROQ_API_KEY,
    )

    chat_completion = client.chat.completions.create(
        messages=[
                {"role": "system", "content": "Summarize the given transcript clearly and concisely."},
                {"role": "user", "content": text}
        ],
        model="llama3-70b-8192",
    )

    return chat_completion.choices[0].message.content


@app.route("/")
def index():
    message = session.pop('message', None)  # Safely pop message from session
    if 'user' not in session:
        return redirect(url_for('signup'))
    return render_template("index.html", message=message)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    message = None  # Initialize message

    if request.method == "POST":
        email = request.form.get("email") or request.json.get("email")
        password = request.form.get("password") or request.json.get("password")

        if not email or not password:
            message = "Email and password are required"
            return render_template("signup.html", message=message)

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        try:
            user = auth.create_user(email=email, password=password)
            db.collection("users").document(user.uid).set({"email": email, "password": hashed_pw})
            session['user'] = email
            return redirect(url_for('index'))
        except auth.EmailAlreadyExistsError:  # Firebase specific error for email duplication
            message = "Account already exists, proceed to Login"
        except Exception as e:
            if "EMAIL_EXISTS" in str(e):
                message = "Account already exists, proceed to Login"
            else:
                message = f"Error: {str(e)}"

    return render_template("signup.html", message=message)

@app.route("/login", methods=["GET", "POST"])
def login():
    message = None  # Initialize message

    if request.method == "POST":
        email = request.form.get("email") or request.json.get("email")
        password = request.form.get("password") or request.json.get("password")

        if not email or not password:
            message = "Email and password are required"
            return render_template("login.html", message=message)

        try:
            user_record = auth.get_user_by_email(email)
            user_doc = db.collection("users").document(user_record.uid).get()

            if not user_doc.exists:
                message = "User not found"
                return render_template("login.html", message=message)

            user_data = user_doc.to_dict()
            stored_password = user_data['password'].encode('utf-8')

            if bcrypt.checkpw(password.encode("utf-8"), stored_password):
                session['user'] = email
                return redirect(url_for('index'))
            
            message = "Invalid credentials"
            return render_template("login.html", message=message)
        
        except auth.UserNotFoundError:
            message = "User not found"
            return render_template("login.html", message=message)
        except Exception as e:
            message = f"Error: {str(e)}"
            return render_template("login.html", message=message)

    return render_template("login.html", message=message)


@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route("/summarize", methods=["POST"])
def summarize():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    video_url = data.get("video_url")
    if not video_url:
        return jsonify({"error": "No video URL provided."}), 400

    transcript = get_youtube_transcript(video_url)
    if "Error" in transcript or transcript == "Invalid YouTube URL":
        return jsonify({"error": transcript}), 400

    # Token-safe chunking (approximate split by words)
    def chunk_text(text, max_words=700):  # Roughly 4500 tokens ≈ 700-800 words depending on the transcript
        words = text.split()
        return [" ".join(words[i:i + max_words]) for i in range(0, len(words), max_words)]

    chunks = chunk_text(transcript)
    client = Groq(api_key=GROQ_API_KEY)
    chunk_summaries = []

    # Step 1: Summarize each chunk individually
    for idx, chunk in enumerate(chunks):
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "Summarize the following transcript chunk clearly and concisely."},
                {"role": "user", "content": chunk}
            ],
            model="llama-3.1-8b-instant",
        )
        chunk_summary = response.choices[0].message.content
        chunk_summaries.append(chunk_summary)

    # Step 2: Meta-summary from chunk summaries
    combined_summaries = "\n\n".join(chunk_summaries)
    final_response = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "Create a final coherent summary from these smaller summaries."},
            {"role": "user", "content": combined_summaries}
        ],
        model="llama3-8b-8192",
    )
    final_summary = final_response.choices[0].message.content

    # Step 3: Save to Firestore
    db.collection("summaries").add({"user": session['user'], "video_url": video_url, "summary": final_summary})
    return jsonify({"summary": final_summary})


if __name__ == "__main__":
    app.run(host='0.0.0.0',debug=True)
