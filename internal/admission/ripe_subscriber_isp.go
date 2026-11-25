package admission

import "vansail-ip-atlas/internal/intelligence"

// Each positive rule requires the operator's own maintainer, country, allocation
// status and complete ordered set of descriptions. All other registry objects
// are negative boundaries for inheritance. Free text never enters a fact.
type ripeSubscriberEvidence struct {
	country, maintainer, status string
	descriptions                [5]ripeDescription
	count                       int
	invalid                     bool
}

func (e *ripeSubscriberEvidence) observe(attr string, value []byte) {
	if e.invalid {
		return
	}
	switch attr {
	case "country":
		switch string(value) {
		case "DE", "BE", "SA", "PL":
			if e.country == "" {
				e.country = string(value)
				return
			}
		}
	case "mnt-by":
		switch string(value) {
		case "NORDERSTEDT-MNT", "TELENET-DBM", "SAUDINET-STC", "VECTRANET-MNT":
			if e.maintainer == "" {
				e.maintainer = string(value)
				return
			}
		}
	case "status":
		switch string(value) {
		case "ASSIGNED", "AGGREGATED-BY-LIR", "ALLOCATED-BY-LIR":
			if e.status == "" {
				e.status = string(value)
				return
			}
		}
	case "descr":
		if e.count < len(e.descriptions) {
			if code := ripeSubscriberDescription(value); code != unrecognizedDescription {
				e.descriptions[e.count] = code
				e.count++
				return
			}
		}
	}
	e.invalid = true
}

// Compact tags retain only reviewed institutional text while the parser reads
// an entire multi-gigabyte export. Distinct service descriptions may establish
// the same ISP. None establish the usage or assignment mode of an address.
type ripeDescription uint8

const (
	unrecognizedDescription ripeDescription = iota
	pppoeCustomers
	wilhelmCompany
	wilhelmStreet
	wilhelmCity
	germany
	telenetBroadband
	vectraUsers
	vectraService
	stcResidential
)

func ripeSubscriberDescription(value []byte) ripeDescription {
	switch string(value) {
	case "PPPOE Private Customers":
		return pppoeCustomers
	case "wilhelm.tel GmbH":
		return wilhelmCompany
	case "Heidbergstr. 101-111":
		return wilhelmStreet
	case "D-22846 Norderstedt":
		return wilhelmCity
	case "Germany":
		return germany
	case "Telenet N.V. Fixed Residential Broadband", "Telenet N.V. Mobile Residential Broadband":
		return telenetBroadband
	case "Broadband users of Vectra S.A", "Broadband users of Vectra S.A.":
		return vectraUsers
	case "-= VECTRA BROADBAND USERS =-":
		return vectraService
	case "STC, Al-Qassim Residential Fixed-Broadband", "STC, Al-Qassim Residential Mobile-Broadband",
		"STC, Dammam Residential Fixed Wireless-Access", "STC, Dammam Residential Fixed-Broadband",
		"STC, Dammam Residential Mobile-Broadband", "STC, Jeddah Residential Fixed Wireless-Access",
		"STC, Jeddah Residential Fixed-Broadband", "STC, Jeddah Residential Mobile-Broadband",
		"STC, Khamis Mushait Residential Fixed-Broadband", "STC, Khobar Residential Fixed-Broadband",
		"STC, Khobar Residential Mobile-Broadband", "STC, Madinah Residential Fixed Wireless-Access",
		"STC, Madinah Residential Fixed-Broadband", "STC, Madinah Residential Mobile-Broadband",
		"STC, Makkah Residential Fixed-Broadband", "STC, Makkah Residential Mobile-Broadband",
		"STC, Riyadh Residential Fixed Wireless-Access", "STC, Riyadh Residential Fixed-Broadband",
		"STC, Riyadh Residential Mobile-Broadband":
		return stcResidential
	}
	return unrecognizedDescription
}

func (e *ripeSubscriberEvidence) operator(registeredName string) intelligence.RIPESubscriberISP {
	if registeredName == "" || e.invalid {
		return intelligence.RIPEUnknownISP
	}
	descriptions := e.descriptions
	switch e.maintainer {
	case "NORDERSTEDT-MNT":
		if e.country == "DE" && (e.status == "ASSIGNED" || e.status == "AGGREGATED-BY-LIR") && (descriptions == [5]ripeDescription{pppoeCustomers, wilhelmCompany, wilhelmStreet, wilhelmCity} ||
			descriptions == [5]ripeDescription{pppoeCustomers, wilhelmCompany, wilhelmStreet, wilhelmCity, germany}) {
			return intelligence.RIPEWilhelmTel
		}
	case "TELENET-DBM":
		if e.country == "BE" && (e.status == "ALLOCATED-BY-LIR" || e.status == "AGGREGATED-BY-LIR") && descriptions == [5]ripeDescription{telenetBroadband} {
			return intelligence.RIPETelenet
		}
	case "SAUDINET-STC":
		if e.country == "SA" && (e.status == "ALLOCATED-BY-LIR" || e.status == "ASSIGNED") && descriptions == [5]ripeDescription{stcResidential} {
			return intelligence.RIPESTC
		}
	case "VECTRANET-MNT":
		if e.country == "PL" && (e.status == "ALLOCATED-BY-LIR" || e.status == "AGGREGATED-BY-LIR") && descriptions == [5]ripeDescription{vectraUsers, vectraService} {
			return intelligence.RIPEVectra
		}
	}
	return intelligence.RIPEUnknownISP
}
