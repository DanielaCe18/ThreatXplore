def robotstxtAvailable(url):
    url += "/robots.txt"
    try:
        sonuc = requests.get(url, verify=False)
        if int(sonuc.status_code) == 200:
            print "[+]robots.txt available"
            print "robots.txt:", sonuc.content
            raporIcerik="[+]robots.txt available\n"
            raporIcerik+="robots.txt:"+sonuc.content+"\n"
            rapor = open(dosyaAdi, "a")
            rapor.write(raporIcerik)
            rapor.close()
    except:
        print "[-]robots.txt isn't available"
        print "robots.txt:", sonuc.content
        raporIcerik = "[-]robots.txt isn't available\n"
        rapor = open(dosyaAdi, "a")
        rapor.write(raporIcerik)
        rapor.close()
