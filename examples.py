"""Built-in sample messages for the ScamShield AI demo.

A spread across English, Hindi and Hinglish and across scam playbooks, plus a
genuinely-safe message so users can see the "LIKELY SAFE" verdict too.
"""

EXAMPLE_MESSAGES: list[str] = [
    # KYC / account-block phishing (Hinglish)
    "Dear customer, your SBI account will be BLOCKED today. Complete your KYC "
    "now: http://sbi-kyc-update.xyz/verify . Urgent action required.",

    # Electricity disconnection (very common Indian SMS scam)
    "Dear consumer, your electricity power will be disconnected tonight at 9:30 "
    "PM because your previous bill was not updated. Please call our officer "
    "immediately at 8123456789.",

    # Digital arrest / authority impersonation
    "This is from CBI Cyber Cell. A parcel in your name contains illegal items. "
    "An FIR has been registered. To avoid digital arrest, join this WhatsApp "
    "video call and transfer the verification amount immediately.",

    # Lottery / prize (Hindi)
    "बधाई हो! आपने KBC लकी ड्रॉ में 25 लाख रुपये जीते हैं। अपना इनाम पाने के लिए "
    "रजिस्ट्रेशन फीस भेजें और इस लिंक पर क्लिक करें: http://kbc-winner.top/claim",

    # Courier / parcel customs fee
    "FedEx: Your parcel is on hold at customs. A clearance fee of Rs 1,250 is "
    "pending. Pay now to release your shipment: https://bit.ly/fedex-clear",

    # Fake job / task scam (Hinglish)
    "Hi! Ghar baithe daily ₹5000 kamao. Part time job, sirf mobile chahiye. "
    "Join karne ke liye registration fee ₹499 pay karo. WhatsApp: 9876543210",

    # OTP request
    "Your account has unusual activity. Share the OTP you just received to verify "
    "your identity and avoid suspension. Reply with the 6 digit code now.",

    # Genuinely safe message
    "Hi, this is a reminder that our team meeting is scheduled for tomorrow at "
    "11 AM in Conference Room 2. Please bring the Q3 report. Thanks!",
]
