# 🕵️ Truth in Traces  

A Windows Vulnerability and Network Scanner for Forensic Security Analysis

Truth in Traces is a powerful tool designed to aid forensic investigators and cybersecurity professionals in detecting system vulnerabilities, analyzing network configurations, and generating real-time forensic scan reports. Built using React (frontend) and Flask (backend), this tool is tailored to streamline forensic audits and security assessments on Windows systems.


## 🔍 Features

- ✅ Real-time system info and vulnerability scanning
- 🔒 Role-based login with JWT authentication
- 🌐 Open ports and firewall rule analysis
- 📄 PDF report generation with system and scan details
- 💬 Live scan logs via Server-Sent Events (SSE)
- 🗂️ Scan history saved to MongoDB with viewing support
- 📊 Clean and responsive React dashboard (with dark mode support)


## 🚀 Tech Stack

- Frontend: React.js (Bootstrap)
- Backend: Flask (Python)
- Authentication: JWT (JSON Web Tokens)
- Database: MongoDB
- PDF Report: ReportLab / xhtml2pdf (PDF generation)
- Real-time Logs: Server-Sent Events (SSE)
- CVE Lookup: NVD API for real-time CVE data


## 📁 Project Structure 

📦 truth-in-traces/
├── backend/
│ ├── app.py
│ ├── routes/
│ ├── scanner/
│ ├── utils/
│ └── templates/ (for PDF)
├── frontend/
│ ├── src/
│ ├── components/
│ ├── pages/
│ └── styles/
└── README.md



## 📌 How to Run

### 🐍 Backend (Flask)

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
Run Flask server:

python app.py
Make sure MongoDB is running and credentials are configured in .env.

⚛️ Frontend (React)
Navigate to frontend folder:

cd frontend
Install dependencies:

npm install
Start development server:

npm run dev
📥 Deployment Notes
You can deploy the frontend on Vercel/Netlify and backend on Render/Heroku or use Docker for combined deployment.

Email credentials, MongoDB URI, and CVE API keys must be secured using environment variables.

🛡️ Use Case Scenarios
Digital forensic labs

Security audit teams

Penetration testers

Cybersecurity education and training

📌 TODO / Future Enhancements
🔁 Scheduling automatic scans

📂 Export scan history as CSV

🧠 AI-based vulnerability risk scoring

🧑‍💼 Multi-user support with user roles

🔐 Encrypted scan results storage

📃 License
MIT License — Feel free to fork, improve, and share!

🙋‍♀️ Made with ❤️ by a forensic science & cybersecurity enthusiast.

