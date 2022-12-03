
import pickle


def main():
    dict = {}
    dict['macOS'] = {'6ec08acc3d9d1cdda756314fb3c5545f.fp.measure.office.com', 'stocks-data-service.lb-apple.com.akadns.net', 'o7f2hmf6xhyv4e4az43ndukcq2ankgqtr2fnij6a7c0bca7a4df8f338sac.d.aa.online-metrix.net', 'o7f2hmf62vshmvi5mvamg24hjcgu34yv7tyw6wvq889b6cdaf02e60adsac.d.aa.online-metrix.net', 'undefined.lan','vuclipi-a.akamaihd.net'}
    dict['Windows'] = {'131-aqo-225.mktoresp.com'}
    dict['Android'] = {'clients.google.com', 'pool.ntp.org'}
    dict['Linux'] = {'idsync.rlcdn.com', '131-aqo-225.mktoresp.com', 'e2c32.gcp.gvt2.com', 'r1---sn-ax5go-q4fs.gvt1.com', 'lh5.googleusercontent.com', 'beacons3.gvt2.com'}

    dictfile = open('osProfiles.p', 'wb')

    pickle.dump(dict, dictfile)                     
    dictfile.close()

    return 

if __name__ == '__main__':
    main()
