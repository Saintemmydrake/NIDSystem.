from drop import store

print(f"you selected..  {store}")
if store == "Packet_Sniffer":
    with open("sniffer.py") as p:
        packet = p.read()
        exec(packet)
elif store == "Traffic Analyzer":
    with open("traffic_analyzer.py")as t:
        traffic = t.read()
        exec(traffic)
elif store == "Anomaly Detector":
    with open("emailing.py") as a:
        ano = a.read()
        exec(ano)
else:
    print("Actions Denied!")




