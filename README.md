# SAC

SAC (Sovereign Alternative to Cloud) est un client écrit en Rust.

Il permet de stocker des fichiers sur différents fournisseurs cloud tout en conservant la maîtrise des clés cryptographiques utilisées pour leur protection.

SAC repose sur une architecture d'enveloppe cryptographique.

Chaque fichier est chiffré localement à l'aide d'une Content Encryption Key (CEK) générée aléatoirement. Cette CEK est ensuite protégée par une Key Encryption Key (KEK) stockée dans un keystore Ethertrust.

Le cloud stocke uniquement :
- le fichier chiffré ;
- la CEK protégée ;
- les métadonnées cryptographiques nécessaires au déchiffrement.

La KEK ne quitte jamais le keystore. Les opérations de wrap et d'unwrap de la CEK sont réalisées via le keystore Ethertrust, accessible par TLS-PSK ou TLS-SE (https://www.ietf.org/archive/id/draft-urien-tls-se-xauth-03.txt).

## Dépendances externes

### Keystore Ethertrust

SAC interagit avec les keystores Ethertrust (https://github.com/purien/keystore) pour les opérations de protection et de déprotection des clés de chiffrement.

### TLS Secure Element

L'accès aux keystores via un Secure Element nécessite un Monolith Ethertrust (https://lemonolith.com/lem.html) et repose sur le binaire `tlsse` fourni par le projet Personal Network HSM (https://github.com/purien/pnhsm).

Dans ce mode, les opérations cryptographiques sensibles peuvent être déléguées au Secure Element. L'authentification TLS auprès du keystore est alors réalisée par l'intermédiaire de `tlsse`.

## Installation 
### Installer Rust
``` bash
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
rustup default stable
```

### Compiler le projet
``` bash
cargo build
```
Le binaire sera disponible dans :
target/debug/sac

### Exécuter le projet
``` bash
cargo run
```

### Compiler en mode release
``` bash
cargo build --release
```
Le binaire sera disponible dans :
target/release/sac

### Exécuter en mode release
``` bash
cargo run --release
```
---

## Configuration
Le client lit sa configuration dans le fichier `config.yaml`.

## Configuration du keystore

SAC supporte actuellement :

- `direct_psk`
- `se_wifi`

Les modes TLS-SE USB et Bluetooth ne sont pas encore intégrés au client mais possible avec LeMonolith

#### Connexion directe au keystore (TLS-PSK)

Dans ce mode, le client se connecte directement au keystore Ethertrust à l’aide d’une identité TLS-PSK et d’une clé pré-partagée.

A indiquer dans le `config.yaml`:

```yaml 
keystore:
  connection_mode: direct_psk

  host: ...
  port: ...
  sni: ...

  slot: ...

  keystore_identity: ...
  keystore_psk: ...
```
##### Paramètres
| Champ             | Description                                        |
| ----------------- | -------------------------------------------------- |
| host              | Adresse IP ou nom DNS du keystore                  |
| port              | Port TLS du keystore                               |
| sni               | Nom de serveur TLS (Server Name Indication)        |
| slot              | Slot de la clé maître utilisée pour le wrap/unwrap les CEK |
| keystore_identity | Identité TLS-PSK                                   |
| keystore_psk      | Clé pré-partagée TLS-PSK en hexadécimal            |
---

#### Connexion via Secure Element (TLS-SE WiFi)

Dans ce mode, le client utilise le programme `tlsse` pour déléguer l’authentification à un Secure Element compatible TLS-SE.

A indiquer dans le `config.yaml`:

```yaml
tlsse: ../../pnhsm/ubuntu/tlsse

keystore:
  connection_mode: se_wifi

  host: ...
  port: ...
  sni: ...

  slot: ...

  keystore_identity: ...

  secure_element:
    host: ...
    port: ...
    sni: ...

    se_identity: ...
    se_psk: ...
```

##### Paramètres
| Champ                      | Description                                        |
| -------------------------- | -------------------------------------------------- |
| tlsse                      | Chemin vers le binaire `tlsse` (https://github.com/purien/pnhsm/blob/main/ubuntu/tlsse)                     |
| host                       | Adresse IP ou nom DNS du keystore                  |
| port                       | Port TLS du keystore                               |
| sni                        | Nom de serveur TLS du keystore                     |
| slot                       | Slot de la clé maître utilisée pour le wrap/unwrap les CEK |
| keystore_identity          | Identité utilisée auprès du keystore               |
| secure_element.host        | Adresse IP du Secure Element                       |
| secure_element.port        | Port TLS du Secure Element                         |
| secure_element.sni         | SNI du Secure Element                              |
| secure_element.se_identity | Identité TLS-PSK du Secure Element                 |
| secure_element.se_psk      | Clé pré-partagée TLS-PSK du Secure Element         |
---

### Configuration du cloud

#### Stockage local

A indiquer dans le `config.yaml`:

```yaml
cloud:
  provider: local
  root: storage
```
##### Paramètres
| Champ                      | Description                                        |
| -------------------------- | -------------------------------------------------- |
| provider      | Provider cloud utilisé                              |
| root      | Répertoire racine de stockage                              |
--- 

#### Azure Blob Storage

A indiquer dans le `config.yaml`:

```yaml
cloud:
  provider: azure
  credentials_path: credentials/azure.credentials
  container: ...
```

Le fichier `credentials/azure.credentials` contient :

```text
DefaultEndpointsProtocol=https;
AccountName=...;
AccountKey=...;
EndpointSuffix=core.windows.net
```

##### Paramètres de configuration

| Champ | Description |
|---------|---------|
| provider | Provider cloud utilisé (`azure`) |
| credentials_path | Chemin vers le fichier de credentials Azure |
| container | Container Blob utilisé pour le stockage |

##### Paramètres du fichier credentials

| Paramètre | Description |
|---------|---------|
| DefaultEndpointsProtocol | Protocole utilisé pour la connexion |
| AccountName | Nom du compte Azure Storage |
| AccountKey | Clé d'accès du compte Azure Storage |
| EndpointSuffix | Suffixe Azure Storage (`core.windows.net`) |

#### SharePoint

A indiquer dans le `config.yaml`:

```yaml
cloud:
  provider: sharepoint
  credentials_path: credentials/sharepoint.credentials
```

Le fichier `credentials/sharepoint.credentials` contient :

```text
tenant_id=...
client_id=...
client_secret=...
sharepoint_hostname=xxx.sharepoint.com
sharepoint_site_path=sites/...
```

##### Paramètres de configuration

| Champ | Description |
|---------|---------|
| provider | Provider cloud utilisé (`sharepoint`) |
| credentials_path | Chemin vers le fichier de credentials SharePoint |

##### Paramètres du fichier credentials

| Paramètre | Description |
|---------|---------|
| tenant_id | Identifiant Microsoft Entra ID (Azure AD) du tenant |
| client_id | Identifiant de l'application enregistrée |
| client_secret | Secret associé à l'application |
| sharepoint_hostname | Nom d'hôte SharePoint (ex: `company.sharepoint.com`) |
| sharepoint_site_path | Chemin du site SharePoint (ex: `sites/MySite`) |

## Fonctionnement cryptographique
Pour chaque fichier :
1.  Une CEK (Content Encryption Key) de 256 bits est générée aléatoirement.
2.  Le contenu du fichier est chiffré avec AES-256-GCM.
3.  La CEK est protégée à l’aide d’une clé maître stockée dans le keystore Ethertrust.
4.  Le fichier chiffré et ses métadonnées sont stockés sur le cloud.
Le keystore n’a jamais accès au contenu du fichier.
Le cloud n’a jamais accès à la CEK en clair.

## Protection de la CEK
La CEK est protégée à l’aide d’une construction CTR reposant sur une clé maître stockée dans le keystore.
Algorithme de chiffrement des données :
```text
AES256_GCM
```

Algorithme de protection de la CEK :
```text
AES128_CTR
```

Deux modes de protection de la CEK sont actuellement supportés :
1.  connexion directe au keystore via TLS-PSK (direct_psk)
2.  connexion au keystore via un Secure Element TLS-SE (se_wifi)

## Métadonnées
Les métadonnées stockées avec chaque fichier utilisent le format suivant :
```json
{
  "WrappedCEK": {
    "Algorithm": "AES128_CTR",
    "KeyId": "1",
    "EncryptedKey": "nonce_ctr || wrapped_cek"
  },
  "EncryptionData": {
    "EncryptionAlgorithm": "AES256_GCM"
  }
}
```
Ce format est indépendant du provider cloud utilisé.
Les nonces sont stockés avec les objets auxquels ils appartiennent.
Le nonce AES-GCM utilisé pour chiffrer le fichier est préfixé au fichier chiffré: `nonce_gcm || ciphertext_gcm`

Le nonce AES-CTR utilisé pour protéger la CEK est préfixé à la clé protégée: `nonce_ctr || wrapped_cek`

## Utilisation de l'interface graphique

### Navigation

Au lancement, SAC affiche le contenu du répertoire cloud courant.

Double-cliquer sur un dossier pour l'ouvrir.
Utiliser le bouton Up pour revenir au dossier parent.
Utiliser Refresh pour actualiser l'affichage.

### Téléverser un fichier

Ouvrir le dossier de destination.
Cliquer sur Upload file.
Sélectionner un fichier local.

Le fichier est alors :

chiffré localement ;
sa CEK est protégée par le keystore ;
le fichier chiffré est envoyé sur le cloud.

### Télécharger un fichier

Sélectionner un fichier.
Cliquer sur Download file.
Choisir le chemin de destination.

Le fichier est automatiquement déchiffré avant d'être écrit sur le disque.

### Créer un dossier

Saisir un nom dans le champ New folder.
Cliquer sur Create folder.

### Supprimer un élément

Sélectionner un fichier ou un dossier.
Cliquer sur Delete selected.