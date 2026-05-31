# Geo data attribution

`country_ipv4.csv.gz` is the **GeoFeed + Whois + ASN** country database
(`geo-whois-asn-country`) from
[sapics/ip-location-db](https://github.com/sapics/ip-location-db).

The underlying IP-to-country data is derived from Regional Internet Registry
(RIR) whois records and is licensed **CC BY 4.0** by the
[Number Resource Organization (NRO)](https://www.nro.net/):

> Data source licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
> by the [NRO](https://www.nro.net/).

This satisfies the CC BY 4.0 attribution requirement. No modifications are made
to the range/country mappings; the CSV is only recompressed (gzip) for embedding.

`country_names.tsv` (ISO 3166-1 alpha-2 → English country name) is derived from
the public ISO 3166 country list.

The data is used offline only: rofk never sends a proxy's egress IP to an
external geolocation service.
