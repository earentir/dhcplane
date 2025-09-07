CGO_ENABLED=0 go build && sudo setcap 'cap_net_bind_service=+ep' ./dhcplane
getcap ./dhcplane
