<<<<<<< HEAD
# YouTube Summarizer

## Overview
The **YouTube Summarizer** is a Flask web application that extracts and summarizes the transcript of a YouTube video using Google Gemini AI. This tool helps users quickly grasp the key points of a video without watching the entire content.

## Features
- Extracts transcripts from YouTube videos.
- Uses **Google Gemini AI** to generate concise summaries.
- Simple and elegant UI for a seamless user experience.

## Tech Stack
- **Backend:** Flask (Python)
- **AI Model:** Google Gemini AI
- **YouTube Transcript API:** youtube_transcript_api
- **Frontend:** HTML, CSS (Rendered via Flask templates)

## Installation

### 1. Clone the Repository
```sh
git clone https://github.com/Afolabi-cyber/Youtube-Summarizer-App
cd YOUR_REPO
```

### 2. Create a Virtual Environment (Optional but Recommended)
```sh
python -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate    # On Windows
```

### 3. Install Dependencies
```sh
pip install -r requirements.txt
```

### 4. Set Up Environment Variables
Create a `.env` file in the root directory and add:
```sh
GROQ_API_KEY=your_groq_api_key
```

### 5. Run the Application
```sh
python main.py
```
The app will run on `http://127.0.0.1:5000/` by default.

## Usage
1. Open the web app in your browser.
2. Enter a **YouTube video URL**.
3. Click on **Summarize** to generate a short summary of the video content.

## Example Output
```
Video Title: "How AI is Changing the World"
Summary: "AI is revolutionizing various industries, including healthcare, finance, and automation..."
```

## Contributing
Feel free to fork this repository, submit issues, or create pull requests to improve the project.

## License
This project is licensed under the MIT License.

## Author
[Afolabi-cyber]([https://github.com/Afolabi-cyber])

=======
# TubeSnap
This App takes a YouTube URL and returns the summary of the YOUTUBE video. 
>>>>>>> 8283654cd76270cc61371af5f5d9d95f71cc3df6

