import os
import time
def notif_sms(message,smsrecipient):
    print("Generating SMS Body.\n")
    sms_body = '%0A'.join([message])
    print(sms_body)
    sms_cmd = r'curl --data "apikey=xxxxxxxxxxxxxxxxxxxxxxxxx&sendername=Emerson&number=NUMBER&message=MESSAGE" https://semaphore.co/api/v4/messages'
    send_cmd = sms_cmd.replace('MESSAGE', sms_body).replace('NUMBER', smsrecipient)

    os.popen(send_cmd).read()
    print("\nSending out SMS Notification to " + smsrecipient)
    print("Done.")
notif_sms('bon','xxxxxxxxxxxxxxx')