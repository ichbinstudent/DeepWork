use super::*;

#[test]
fn cuts_only_peoples_web_connections() {
    let listing = "\
0      0      10.0.0.5:52360 203.0.113.7:443 uid:1000 ino:1 sk:1 cgroup:/user.slice <->
0      0      10.0.0.5:52361 203.0.113.7:443 timer:(keepalive,24sec,0) uid:1001 ino:2 sk:2 <->
0      0      10.0.0.5:52362 203.0.113.7:443 ino:3 sk:3 cgroup:/system.slice/apt.service <->
0      0      10.0.0.5:52363 203.0.113.7:443 uid:110 ino:4 sk:4 <->
0      0      10.0.0.5:52364 203.0.113.9:443 uid:1000 ino:5 sk:5 <->
0      0      10.0.0.5:52365 203.0.113.7:8080 uid:1000 ino:6 sk:6 <->
0      0      10.0.0.5:22    203.0.113.7:51234 ino:7 sk:7 <->
0      0      [2001:db8::5]:40000 [2001:db8::7]:80 uid:1000 ino:8 sk:8 <->
0      0      [::ffff:10.0.0.5]:40001 [::ffff:203.0.113.7]:443 uid:1000 ino:9 sk:9 <->
garbage
";
    let ips: HashSet<IpAddr> = ["203.0.113.7", "2001:db8::7"]
        .iter()
        .map(|ip| ip.parse().unwrap())
        .collect();
    let cut = web_connections(listing, &ips, 1000);
    let peers: Vec<(&str, &str)> = cut.iter().map(|(l, p)| (l.as_str(), p.as_str())).collect();
    assert_eq!(
        peers,
        [
            ("10.0.0.5:52360", "203.0.113.7:443"),
            ("10.0.0.5:52361", "203.0.113.7:443"),
            ("[2001:db8::5]:40000", "[2001:db8::7]:80"),
            ("[::ffff:10.0.0.5]:40001", "[::ffff:203.0.113.7]:443"),
        ]
    );
}
