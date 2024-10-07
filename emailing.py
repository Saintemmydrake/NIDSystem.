import smtplib
from anomalies_detection import malformed_packets, malicious_packets, suspected_scanners
from drop import user_email


def sendmail(msg):
    try:
        storing = em
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login("saintemmydrake2@gmail.com", "rdkw ktsu gjwu fkth")
        subject = 'Alert Notification'
        email_message = f'subject: {subject}\n\n {msg}'
        server.sendmail(
           'saintemmydrake2@gmail.com',
            to_addrs=user_email,
            msg= email_message)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print(f'failed to send email: {e}')

def main():
    if len(malicious_packets) >= 1:
        sendmail(f'Number of malicious packet detected: {len(malicious_packets)}')
    elif len(suspected_scanners) >= 0:
        sendmail(f"Suspected scanners: "
            f"{suspected_scanners}")
    elif len(malformed_packets) >= 0:
        sendmail(f"Number of malformed packet detected: {len(malformed_packets)}")
    else:
        pass
if __name__ == "__main__":
    main()








