import threading
import time
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from db_adapter import db_adapter
from utils.fee_calculator import get_fee_status

def check_and_send_reminders():
    print("[FEE_CHECKER] Running automated fee check cycle...")
    
    # Wait to ensure db is ready
    time.sleep(10)
    
    sender_email = os.getenv("SENDER_EMAIL")
    app_password = os.getenv("APP_PASSWORD")
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    
    if not sender_email or not app_password:
        print("[FEE_CHECKER] WARNING: SMTP credentials not set. Cannot send emails.")
        return

    while True:
        try:
            conn = db_adapter.get_connection()
            
            # Ensure column exists for tracking (safe for Postgres and SQLite)
            try:
                conn.execute("ALTER TABLE students ADD COLUMN IF NOT EXISTS fee_reminder_sent TIMESTAMP")
                conn.commit()
            except Exception as e:
                # If column already exists or syntax differs slightly, ignore and proceed
                pass

            # Fetch all students
            students = conn.fetchall("SELECT s.id, s.user_id, s.fees_paid, u.email, u.name, s.fee_reminder_sent FROM students s JOIN users u ON s.user_id = u.id")
            
            for student in students:
                fees_paid = student["fees_paid"] or 0
                fee_status = get_fee_status(fees_paid)
                
                # If they owe money NOW
                if fee_status["is_overdue"]:
                    last_reminder = student["fee_reminder_sent"]
                    send_needed = False
                    
                    if not last_reminder:
                        send_needed = True
                    else:
                        # Only send one reminder every 7 days if they are continuously overdue
                        last_date = last_reminder
                        if isinstance(last_date, str):
                            try:
                                last_date = datetime.fromisoformat(last_date.replace('Z', '+00:00')[:19])
                            except:
                                last_date = None
                        
                        if last_date and (datetime.utcnow() - last_date.replace(tzinfo=None)).days >= 7:
                            send_needed = True

                    if send_needed and student["email"]:
                        print(f"[FEE_CHECKER] Sending fee reminder to {student['email']}")
                        try:
                            msg = MIMEMultipart("alternative")
                            msg["Subject"] = f"Action Required: Outstanding Fee Balance ({fee_status['active_quarter']})"
                            msg["From"] = sender_email
                            msg["To"] = student["email"]

                            html = f"""
                            <html>
                                <body>
                                    <h2>Fee Payment Required</h2>
                                    <p>Dear {student['name']},</p>
                                    <p>This is an automated notification from the Zero-Trust Student Portal.</p>
                                    <p>You currently have an overdue balance for <strong>{fee_status['active_quarter']}</strong>.</p>
                                    <ul>
                                        <li><strong>Amount Due Now:</strong> ₹{fee_status['current_due']}</li>
                                        <li><strong>Total Remaining for Year:</strong> ₹{fee_status['total_remaining']}</li>
                                    </ul>
                                    <p>Please log in to the portal securely to process your payment.</p>
                                    <p>Thank you.</p>
                                </body>
                            </html>
                            """
                            msg.attach(MIMEText(html, "html"))

                            with smtplib.SMTP(smtp_server, smtp_port) as server:
                                server.starttls()
                                server.login(sender_email, app_password)
                                server.sendmail(sender_email, student["email"], msg.as_string())
                            
                            # Mark as sent
                            conn.execute(
                                "UPDATE students SET fee_reminder_sent = %s WHERE id = %s" if db_adapter.is_postgres else "UPDATE students SET fee_reminder_sent = ? WHERE id = ?",
                                (datetime.utcnow().isoformat(), student["id"])
                            )
                            conn.commit()
                        except Exception as email_e:
                            print(f"[FEE_CHECKER] Failed to send email to {student['email']}: {email_e}")

            conn.close()
        except Exception as e:
            print(f"[FEE_CHECKER] Error during cycle: {e}")
            
        # Run check every 12 hours
        time.sleep(12 * 3600)

def start_background_fee_checker():
    thread = threading.Thread(target=check_and_send_reminders, daemon=True)
    thread.start()
