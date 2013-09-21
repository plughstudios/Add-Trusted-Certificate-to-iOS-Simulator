for x in ~/Library/Application\ Support/iPhone\ Simulator/*/Library/Keychains/TrustStore.sqlite3; do 
  cp TrustStore.sqlite3 "${x}"
done
