# SDP Catcher

SDP Catcher centralise les annonces SAP/SDP d'un réseau audio AES67 dans une
application Windows. Il affiche les flux par interface, conserve un cache local,
permet d'enregistrer les fichiers SDP et surveille le Grandmaster PTPv2.

## Réseau multicast

Au démarrage d'une capture, l'application rejoint explicitement les groupes SAP
IPv4 suivants sur chaque interface sélectionnée :

- `239.255.255.255` — SAP dans le scope administratif local habituel ;
- `224.2.127.254` — SAP dans le scope IPv4 global défini par le RFC 2974.

Cette adhésion génère les rapports IGMP nécessaires aux switches utilisant
l'IGMP Snooping, notamment les Luminex GigaCore. Le Querier IGMP doit rester
actif dans chaque VLAN concerné.

Une interface placée dans un VLAN ne peut découvrir que les annonces de ce
VLAN. Pour plusieurs groupes/VLAN Luminex, utilisez une interface par VLAN, des
sous-interfaces VLAN supportées par Windows et la carte réseau, ou plusieurs
collecteurs.

Filtre de validation Wireshark :

```text
igmp || (ip.dst == 239.255.255.255 && udp.dstport == 9875)
```

## Prérequis

- Windows avec l'architecture Npcap correspondante (x86, x64 ou ARM64) ;
- Npcap installé ;
- droits administrateur, nécessaires à la modification des propriétés IPv4
  depuis l'application ;
- au moins un Querier IGMP actif par VLAN multicast.

## Développement

```text
npm install
npm run tauri dev
```

Vérifications :

```text
npm run build
cd src-tauri
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Le parseur accepte SAPv2/SDP non chiffré, avec ou sans type MIME
`application/sdp`, et prend en charge la compression zlib. Les annonces
chiffrées sont rejetées.
