import os
import json
import requests
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

cred = credentials.Certificate(cred_path)
firebase_admin.initialize_app(cred)
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
        model="llama-3.3-70b-versatile",
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
    if request.method == "POST":
        email = request.form.get("email") or request.json.get("email")
        password = request.form.get("password") or request.json.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        try:
            user = auth.create_user(email=email, password=password)
            db.collection("users").document(user.uid).set({"email": email, "password": hashed_pw})
            session['user'] = email
            return redirect(url_for('index'))
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    session['message'] = "Signed up successfully!"
    # return redirect(url_for('index'))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email") or request.json.get("email")
        password = request.form.get("password") or request.json.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        try:
            user_record = auth.get_user_by_email(email)
            user_doc = db.collection("users").document(user_record.uid).get()

            if not user_doc.exists:
                return jsonify({"error": "User not found"}), 404

            user_data = user_doc.to_dict()
            stored_password = user_data['password'].encode('utf-8')

            if bcrypt.checkpw(password.encode("utf-8"), stored_password):
                session['user'] = email
                return redirect(url_for('index'))
            
            return jsonify({"error": "Invalid credentials"}), 401
        except auth.UserNotFoundError:
            return jsonify({"error": "User not found"}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    session['message'] = "Logged in successfully!"
    # return redirect(url_for('index'))
    
    return render_template("login.html")

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
    
    summary = summarize_with_groq(transcript)
    db.collection("summaries").add({"user": session['user'], "video_url": video_url, "summary": summary})
    return jsonify({"summary": summary})

if __name__ == "__main__":
    app.run(debug=True)