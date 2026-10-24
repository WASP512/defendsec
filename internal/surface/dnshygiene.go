package surface

import (
	"strings"

	"github.com/miekg/dns"
)

// --- DNSSEC ----------------------------------------------------------------

// dnssecCheck reads the delegation (DS at the parent) and, when there is one,
// asks a validating resolver for the zone's SOA with the DO bit and reads the
// AD flag. The observation names the resolver that answered, because "signed"
// here means "this resolver validated it".
//
// A bogus chain is told apart from an outage by repeating the question with
// the checking-disabled bit: if the data comes back with CD but SERVFAILs
// without it, validation is what failed. If it fails either way we simply
// could not find out.
func (r *run) dnssecCheck() CheckResult {
	d := r.a.Value
	ds := r.lookup(Query{Name: d, Type: dns.TypeDS, DO: true, Validating: true})
	obs := map[string]any{"name": d, "resolver": ds.Resolver}
	switch ds.Status {
	case StatusFail:
		return notAssessed(CheckDNSSEC, "DS lookup failed: "+ds.Reason(), obs)
	case StatusNXDomain:
		return notAssessed(CheckDNSSEC, d+" does not exist according to the validating resolver", obs)
	}
	if ds.Status == StatusNoData {
		obs["signed"] = false
		return assessed(CheckDNSSEC, obs, newFinding(CheckDNSSEC, "dnssec.unsigned", d, SevInfo,
			"Domain is not DNSSEC-signed",
			d+" has no DS record at its parent, so its DNS answers are not cryptographically signed. That is the norm for small businesses and not a fault.",
			"Optional: enable DNSSEC at your DNS host and publish the DS record it gives you at your registrar. Do this only if your DNS and registrar both support it, because a broken DS record takes the domain offline for validating resolvers.", obs))
	}
	var dsText []string
	for _, rr := range ds.RRs {
		dsText = append(dsText, rr.String())
	}
	obs["ds"] = dsText
	obs["signed"] = true

	soa := r.lookup(Query{Name: d, Type: dns.TypeSOA, DO: true, Validating: true})
	obs["resolver"] = soa.Resolver
	switch soa.Status {
	case StatusOK:
		obs["ad"] = soa.AD
		if soa.AD {
			obs["validated"] = true
			return assessed(CheckDNSSEC, obs)
		}
		return notAssessed(CheckDNSSEC, "a DS record exists, but the resolver ("+soa.Resolver+") did not set the authenticated-data flag, so it may not be validating; chain not judged", obs)
	case StatusFail:
		cd := r.lookup(Query{Name: d, Type: dns.TypeSOA, DO: true, CD: true, Validating: true})
		obs["withChecksDisabled"] = cd.Status.String()
		if cd.Status == StatusOK {
			obs["validated"] = false
			return assessed(CheckDNSSEC, obs, newFinding(CheckDNSSEC, "dnssec.broken", d, SevHigh,
				"DNSSEC chain of trust is broken",
				d+" has a DS record at its parent, but a validating resolver ("+soa.Resolver+") refuses its answers (SERVFAIL) although they arrive when validation is switched off. Every user behind a validating resolver, including 1.1.1.1, 8.8.8.8 and 9.9.9.9, cannot resolve the domain.",
				"Fix this first: either repair the signatures at your DNS host, or remove the DS record at your registrar to switch DNSSEC off. A DS that does not match the zone's keys is the usual cause, often after a DNS provider change.", obs))
		}
		return notAssessed(CheckDNSSEC, "the resolver answered SERVFAIL even with validation off, so this looks like an outage rather than a DNSSEC failure: "+cd.Reason(), obs)
	}
	return notAssessed(CheckDNSSEC, "SOA lookup returned "+soa.Status.String(), obs)
}

// --- CAA -------------------------------------------------------------------

// caaCheck climbs from the name toward the organisational domain looking for
// the first CAA record set (RFC 8659), as a certificate authority would.
func (r *run) caaCheck() CheckResult {
	d := r.a.Value
	org := orgDomain(d)
	name := d
	var tried []string
	for {
		tried = append(tried, name)
		a := r.lookup(Query{Name: name, Type: dns.TypeCAA})
		if a.Status == StatusFail {
			return notAssessed(CheckCAA, "CAA lookup at "+name+" failed: "+a.Reason(), map[string]any{"tried": tried})
		}
		if a.Status == StatusOK {
			var recs []string
			for _, rr := range a.RRs {
				recs = append(recs, rr.String())
			}
			return assessed(CheckCAA, map[string]any{"foundAt": name, "records": recs, "tried": tried})
		}
		if name == org || !strings.Contains(name, ".") {
			break
		}
		_, name, _ = strings.Cut(name, ".")
	}
	obs := map[string]any{"tried": tried}
	return assessed(CheckCAA, obs, newFinding(CheckCAA, "caa.missing", d, SevLow,
		"No CAA record",
		"No CAA record exists for "+d+" or its parents up to "+org+", so any certificate authority may issue certificates for it.",
		"Publish CAA records naming only the certificate authorities you use, for example '0 issue \"letsencrypt.org\"'. Check which CA your host or CDN uses first, or issuance will start failing.", obs))
}

// --- Dangling CNAME --------------------------------------------------------

var takeoverProne = []struct{ suffix, service string }{
	{".azurewebsites.net", "Azure App Service"},
	{".cloudapp.net", "Azure Cloud Services"},
	{".cloudapp.azure.com", "Azure"},
	{".trafficmanager.net", "Azure Traffic Manager"},
	{".azureedge.net", "Azure CDN"},
	{".blob.core.windows.net", "Azure Blob Storage"},
	{".github.io", "GitHub Pages"},
	{".herokudns.com", "Heroku"},
	{".herokuapp.com", "Heroku"},
	{".elasticbeanstalk.com", "AWS Elastic Beanstalk"},
	{".s3.amazonaws.com", "AWS S3"},
}

func proneService(target string) string {
	t := trimDot(target)
	for _, p := range takeoverProne {
		if strings.HasSuffix(t, p.suffix) {
			return p.service
		}
	}
	if strings.Contains(t, ".s3-website") && strings.HasSuffix(t, ".amazonaws.com") {
		return "AWS S3 website hosting"
	}
	return ""
}

// cnameCheck is best effort: it flags a declared name whose CNAME chain ends in
// a name that does not exist. "Target does not exist" is what was seen; whether
// anyone could claim it depends on the service and is not asserted.
func (r *run) cnameCheck() CheckResult {
	name := r.a.Value
	a := r.lookup(Query{Name: name, Type: dns.TypeA})
	if a.Status == StatusFail {
		return notAssessed(CheckCNAME, "lookup failed: "+a.Reason(), nil)
	}
	var chain []string
	for _, c := range a.CNAMEs {
		chain = append(chain, trimDot(c.Hdr.Name)+" -> "+trimDot(c.Target))
	}
	obs := map[string]any{"name": name, "cnameChain": chain, "rcode": dns.RcodeToString[a.Rcode]}
	if len(a.CNAMEs) == 0 {
		return assessed(CheckCNAME, obs)
	}
	if a.Status != StatusNXDomain {
		return assessed(CheckCNAME, obs)
	}
	target := trimDot(a.CNAMEs[len(a.CNAMEs)-1].Target)
	detail := name + " is an alias (CNAME) whose target " + target + " does not exist in DNS (NXDOMAIN)."
	if svc := proneService(target); svc != "" {
		detail += " The target is on " + svc + ", where an unused name can sometimes be registered by someone else, so check whether it is still yours. That has not been tested and nothing here shows it can be claimed."
	}
	obs["target"] = target
	return assessed(CheckCNAME, obs, newFinding(CheckCNAME, "cname.dangling", name, SevMedium,
		"CNAME points at a name that does not exist",
		detail,
		"If the service behind "+target+" is retired, delete the CNAME record for "+name+". If it should still work, recreate the resource at the provider.", obs))
}
