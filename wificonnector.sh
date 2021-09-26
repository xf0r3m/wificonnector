#!/bin/bash

if [ $(whoami) = "root" ]; then

	echo "[*]Wykrywanie interfejsów sieci bezprzewodowej";
	i=1;
	wlansCount=$(iwconfig 2>/dev/null | grep 'IEEE' | wc -l | awk '{printf $1}');

	while [ $i -le $wlansCount ]; do 

		wlanAdapters[$i]=$(iwconfig 2>/dev/null | grep 'IEEE' | sed -n "${i}p" | awk '{printf $1}');

		if lshw -class network 2>/dev/null | grep "${wlanAdapters[$i]}" > /dev/null; then

			wALineNumber=$(lshw -class network -json 2>/dev/null | grep -n "${wlanAdapters[$i]}" | cut -d ":" -f 1);

			wAVLineNumber=$(expr $wALineNumber - 3);
			wAPLineNumber=$(expr $wALineNumber - 4);

			wlanAdapterVendor=$(lshw -class network -json 2>/dev/null | sed -n "${wAVLineNumber}p" | cut -d ":" -f 2 | sed -e 's/\"//g' -e 's/,//g' -e 's/ /_/');
			wlanAdaptersVendor[$i]=$(echo $wlanAdapterVendor | sed 's/_//');

			wlanAdaptersProduct[$i]=$(lshw -class network -json 2>/dev/null | sed -n "${wAPLineNumber}p" | cut -d ":" -f 2 | sed -e 's/\"//g' -e 's/,//g');

		fi

		i=$(expr $i + 1);

	done 

	echo "[+]Wykryte karty sieciowe WLAN: ";

	i=1;
	while [ $i -le ${#wlanAdapters[*]} ]; do


			echo "${i}) ${wlanAdapters[$i]} \"${wlanAdaptersVendor[$i]}${wlanAdaptersProduct[$i]}\"";

		i=$(expr $i + 1);

	done

	echo -n "Karta: "; read interfaceIndex;

	interface=${wlanAdapters[$interfaceIndex]};

	if ! iwconfig $interface | grep "ESSID:off/any" > /dev/null; then
		connectedNetworkSsid=$(iwconfig $interface | grep 'ESSID' | cut -d ":" -f 2 | sed 's/"//g' | awk '{printf $1}');

		dcConfirm="0";
		while true; do

			if [ $dcConfirm = 'n' ]; then break; fi;
			if [ $dcConfirm = 'y' ]; then break; fi;

			echo -n "[*]To urządzenie jest sparowane z $connectedNetworkSsid. Rozłączyć? [N/y]: "; read dcConfirm;
			dcConfirm=$(echo $dcConfirm | tr [:upper:] [:lower:]);
		done

		if [ $dcConfirm = 'y' ]; then

			wpa_supplicantPID=$(ps -aux | grep 'wpa_supplicant.conf' | head -n 1 | awk '{printf $2}');

			if [ "$wpa_supplicantPID" ]; then 
				kill -9 $wpa_supplicantPID;
				dhclient -r $interface;
			else
				echo "[-]Nie można znaleźć PID wpa_supplicant. Czy połączenie aby na pewno się powiodło.";
			fi
		fi
	fi

	echo "[*]Skanowanie...";

	iwlist $interface scan > .scans 2>/dev/null;
	if [ $? -ne 0 ]; then echo "[-]Skanowanie nie powiodło się"; exit 1; fi

	startList=$(cat .scans | grep -n 'Cell' | cut -d ":" -f 1 | awk '{printf $1" "}');

	i=0;
	for j in $startList; do
		cellOutputStart[$i]=$j;
		i=$(expr $i + 1);
	done


	l=0;
	m=$(expr $l+1);

	while [ $l -le $(expr ${#cellOutputStart[*]} - 1) ]; do

		if [ $l -eq $(expr ${#cellOutputStart[*]} - 1) ]; then 
			cellOutputEnd[$l]=$(cat .scans | wc -l | awk '{printf $1}');
		else
			cellOutputEnd[$l]=$(expr ${cellOutputStart[$m]} - 1);
		fi

		l=$(expr $l + 1);
		m=$(expr $l + 1);

	done

	cellsCount=$(cat .scans | grep 'Cell' | wc -l | awk '{printf $1}');


	i=0;
	while [ $i -le $(expr $cellsCount - 1) ]; do

		bssid[$i]=$(cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "Address: " | awk '{printf $5}');
		essid[$i]=$(cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "ESSID:" | cut -d ":" -f 2 | sed 's/"//g');

		if echo ${essid[$i]} | grep "\x00" > /dev/null; then essid[$i]="\"<hidden>\""; fi

		if [ $(echo ${essid[$i]} | wc -c) -le 3 ]; then essid[$i]="\"<hidden>\""; fi	

		
		channel[$i]=$(cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "Channel:" | cut -d ":" -f 2);
		sl[$i]=$(cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "Signal level" | awk '{printf $3" "$4}' | cut -d "=" -f 2);

		if cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "WPA" > /dev/null; then

			if cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "WPA2 Version 1" > /dev/null; then

				if cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "TKIP" > /dev/null; then
					encryption=4;
				else
					encryption=5;
				fi
			fi

			if cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "WPA Version 1" > /dev/null; then

				if cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "TKIP" > /dev/null; then
					if [ "$encryption" ]; then encryption=$(expr $encryption + 2);
					else encryption=2; fi
				else
					if [ "$encryption" ]; then encryption=$(expr $encryption + 3);
					else encryption=3; fi
				fi

			fi

		else
			if cat .scans | sed -n "${cellOutputStart[$i]},${cellOutputEnd[$i]}p" | grep "Encryption key:on" > /dev/null; then
				encryption=1;
			else
				encryption=0;
			fi

		fi

		case $encryption in

			0) 
				enc[$i]="Open";;
			1)
				enc[$i]="WEP";;
			2)
				enc[$i]="WPA (TKIP)";;
			3)
				enc[$i]="WPA (CCMP)";;
			4)
				enc[$i]="WPA2 (TKIP)";;
			5)
				enc[$i]="WPA2 (CCMP)";;
			6)
				enc[$i]="WPA/WPA2 (TKIP)";;
			8) 
				enc[$i]="WPA/WPA2 (CCMP)";;
			*) 
				enc[$i]="Error";;
		esac
	
		
		i=$(expr $i + 1);

	done

	echo "[+]Wykryte sieci bezprzewodowe: ";
	echo -e "[*]Format: ESSID	Zabezpieczenia | Siła sygnału | Kanał | BSSID";

	i=0;
	while [ $i -lt ${#essid[*]} ]; do

		index=$(expr $i + 1);
		echo "${index}) ${essid[$i]}	\"${enc[$i]} | ${sl[$i]} | ${channel[$i]} | ${bssid[$i]}\"";

		i=$(expr $i + 1);
	done

	echo -n "Siec: "; read networkIndex;
	networkIndex=$(expr $networkIndex - 1);

	echo "${essid[$networkIndex]}: ${enc[$networkIndex]} |  ${sl[$networkIndex]} | ${channel[$networkIndex]} | ${bssid[$networkIndex]}"

	echo "[*]Parowanie z siecią";
	
	if iwconfig $interface | grep "${bssid[$networkIndex]}" > /dev/null; then

		echo "[*]Urządzenie już zostało sparowane z tą siecią.";
		exit 0;
	fi

	if [ ${essid[$networkIndex]} = "\"<hidden>\"" ]; then 
					echo "SSID ukrytej sieci: "; read ssid;
					essid[$networkIndex]=$ssid;
					hiddenNetwork=$networkIndex;
	fi

	case ${enc[$networkIndex]} in

		'Open' ) 
				echo "iwconfig $interface essid ${essid[$i]};";;
		'WEP')
				stty -echo
				echo "Klucz dostępu: "; read enckey;
				stty echo;

				

				echo "iwconfig $interface essid ${essid[$i]} key \"$enckey\"";;
		'WPA (TKIP)' | 'WPA (CCMP)' | 'WPA2 (TKIP)' | 'WPA2 (CCMP)' | 'WPA/WPA2 (TKIP)' | 'WPA/WPA2 (CCMP)')

				stty -echo;
				echo "Klucz dostępu: "; read enckey;
				stty echo;

				if [ $networkIndex -eq $hiddenNetwork ]; then iwconfig $interface essid ${essid[$networkIndex]}; fi

				wpa_passphrase ${essid[$networkIndex]} $enckey > /etc/wpa_supplicant/wpa_supplicant.conf;
				wpa_supplicant -B -c /etc/wpa_supplicant/wpa_supplicant.conf -i $interface;;
		*) echo "Error";;
	esac

		echo "[*]Pobieranie adresu sieciowego";
		sudo dhclient $interface;

		echo '[*]Sprawdzanie połączenia: ';
		ping -c 1 wp.pl > /dev/null 2>1;

		if [ $? -ne 0 ]; then
			echo "[-]Połączenie nie powiodło się";
		else
			echo "[+]Połączenie powiodło się";
		fi






else
	echo "Skrypt musi zostać uruchomiony jako root";
	exit 1;
fi