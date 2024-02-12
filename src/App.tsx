import React, { useState } from 'react';
import { Typography, Card, Button, Timeline, Spin, Divider, Flex, Space, message, Input } from 'antd';
import { LoadingOutlined } from '@ant-design/icons';

function delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

type LogItem = {
  msg: React.ReactNode
  complete: boolean
  id: string
}

async function requestChallengeFromServer(): Promise<Uint8Array> {
  return delay(1500).then(() => Uint8Array.from("very random string", c => c.charCodeAt(0)))
}

async function sendToServer(): Promise<unknown> {
  return delay(1500)
}

const firstSalt = new Uint8Array(new Array(32).fill(1)).buffer;
const fakeNonce = new Uint8Array(new Array(12).fill(1)).buffer;

type RegistrationData = {
  rawId: ArrayBuffer
  transports: AuthenticatorTransport[]
}

async function createCredential(challenge: Uint8Array): Promise<RegistrationData> {
  return navigator.credentials.create({
    publicKey: {
      challenge: challenge,
      rp: {
        name: "User Name",
        id: window.location.hostname
      },
      user: {
        id: Uint8Array.from("user-id-42", c => c.charCodeAt(0)),
        name: "user.name@example.com",
        displayName: "User Name"
      },
      pubKeyCredParams: [
        { alg: -8, type: "public-key" },   // Ed25519
        { alg: -7, type: "public-key" },   // ES256
        { alg: -257, type: "public-key" }, // RS256
      ],
      timeout: 60000,
      attestation: "direct",
      authenticatorSelection: {
        userVerification: "required",
      },
      extensions: {
        // @ts-ignore
        prf: {
          eval: {
            first: firstSalt,
          },
        },
      },

    }
  }).then(credential => {
    console.log("registered credential", credential)
    if (credential == null) {
      throw new Error("Credential Can't be null and sohuld be public extension")
    }
    const pkCredential = credential as PublicKeyCredential
    console.log("registered credential clientExtensionResult", pkCredential.getClientExtensionResults())
    return {
      rawId: pkCredential.rawId,
      // @ts-ignore
      transports: pkCredential.response.getTransports()
    }
  })
}

async function authenticateToEncrypt(challenge: Uint8Array, registrationData: RegistrationData): Promise<CryptoKey> {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: challenge,
      allowCredentials: [
        {
          id: registrationData.rawId,
          transports: registrationData.transports,
          type: "public-key",
        },
      ],
      rpId: window.location.hostname,
      userVerification: "required",
      extensions: {
        // @ts-ignore
        prf: {
          eval: {
            first: firstSalt,
          },
        },
      },
    },
  });
  console.log("authenticated credential", credential);
  if (credential == null) {
    throw new Error("Credential Can't be null and sohuld be public extension");
  }
  const pkCredential = credential as PublicKeyCredential;
  console.log("authenticated credential clientExtensionResult", pkCredential.getClientExtensionResults());
  // @ts-ignore
  const inputKeyMaterial = new Uint8Array(pkCredential.getClientExtensionResults().prf.results.first);
  return crypto.subtle.importKey(
    "raw",
    inputKeyMaterial,
    "HKDF",
    false,
    ["deriveKey"],
  )

}

async function deriveEncryptionKey(key: CryptoKey): Promise<CryptoKey> {
  const info = new TextEncoder().encode("encryption key")
  const salt = new Uint8Array()

  return crypto.subtle.deriveKey(
    { name: "HKDF", info, salt, hash: "SHA-256" },
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
}

function toBase64(buff: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buff)))
}

async function encryptMessage(msg: string, key: CryptoKey): Promise<string> {
  return crypto.subtle.encrypt(
    { name: "AES-GCM", iv: fakeNonce },
    key,
    new TextEncoder().encode(msg),
  ).then((bytes) => toBase64(bytes));
}

async function decryptMessage(msg64: string, key: CryptoKey): Promise<string> {
  const bytes = Uint8Array.from(atob(msg64), c => c.charCodeAt(0))
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fakeNonce },
    key,
    bytes
  ).then((decrypted) => new TextDecoder().decode(decrypted));
}

function App() {
  const [actionsLog, setActionsLog] = useState<Array<LogItem>>([])
  const [registrationData, setRegistrationData] = useState<RegistrationData | null>(null)

  const [encryptionKey, setEncryptionKey] = useState<CryptoKey | null>(null)
  const [decryptionKey, setDecryptionKey] = useState<CryptoKey | null>(null)

  const [toEncrypt, setToEncrypt] = useState<string>("")
  const [toDecrypt, setToDecrypt] = useState<string>("")

  const [messageApi, contextHolder] = message.useMessage();


  const newLogItem = (msg: React.ReactNode, complete: boolean = false): string => {
    var id = crypto.randomUUID()
    setActionsLog((prev) => {
      return prev.concat({ msg: msg, complete: complete, id: id })
    })
    return id
  }

  const setLogItemComplete = (id: string) => {
    setActionsLog((prev) => prev.map((v) => {
      if (v.id === id) {
        const vNxt = { ...v }
        vNxt.complete = true
        return vNxt
      }
      return v
    }))
  }

  const handleException = (reason: any) => {
    messageApi.open({ type: "error", content: "Error occured look at the debug console" })
    console.log("Exception occured", reason)
  }

  const createCredentialAction = () => {
    const challengeLogId = newLogItem("Request server challenge")
    requestChallengeFromServer().then((challenge) => {
      setLogItemComplete(challengeLogId)
      const createCredentialLogId = newLogItem("Create credentials")
      createCredential(challenge).then((registrationData) => {
        setLogItemComplete(createCredentialLogId)
        const sendToServerLogId = newLogItem("Send registration data to server")
        sendToServer().then(() => {
          setLogItemComplete(sendToServerLogId)
          setRegistrationData(registrationData)
        })
      })
    }).catch(handleException)
  }

  const prepareEncryptionKey = () => {
    const challengeLogId = newLogItem("Request server challenge and registered credential id")
    requestChallengeFromServer().then((challenge) => {
      setLogItemComplete(challengeLogId)
      const authenticateForEncryptLogId = newLogItem("Authenticate with token for encryption")
      authenticateToEncrypt(challenge, registrationData!!).then((keyToken) => {
        setLogItemComplete(authenticateForEncryptLogId)
        deriveEncryptionKey(keyToken).then((key) => {
          newLogItem("Derive encryption key", true)
          setEncryptionKey(key)
        })
      })
    }).catch(handleException)
  }

  const prepareDecryptionKey = () => {
    const challengeLogId = newLogItem("Request server challenge and registered credential id")
    requestChallengeFromServer().then((challenge) => {
      setLogItemComplete(challengeLogId)
      const authenticateForDecryptLogId = newLogItem("Authenticate with token for decryption")
      authenticateToEncrypt(challenge, registrationData!!).then((keyToken) => {
        setLogItemComplete(authenticateForDecryptLogId)
        deriveEncryptionKey(keyToken).then((key) => {
          newLogItem("Derive decryption key", true)
          setDecryptionKey(key)
        })
      })
    }).catch(handleException)
  }

  const encryptAction = () => {
    encryptMessage(toEncrypt, encryptionKey!!).then((encryptionResult) => {
      newLogItem(<>Encryption&nbsp;result:&nbsp;<Typography.Text ellipsis copyable code>{encryptionResult}</Typography.Text></>, true)
      navigator.clipboard.writeText(encryptionResult)
      messageApi.open({ type: "success", content: "Message sucessfully encrypted, and copied to clipboard" })
    }).catch(handleException)
  }

  const decryptAction = () => {
    decryptMessage(toDecrypt, encryptionKey!!).then((decryptionResult) => {
      newLogItem("Data decrypted: " + decryptionResult, true)
      messageApi.open({ type: "success", content: "Message sucessfully decrypted: " + decryptionResult })
    }).catch(handleException)
  }

  return (
    <>
      {contextHolder}
      <Flex justify='center' wrap='wrap' gap={24}>
        <Card title="Flow" style={{ width: "500px" }}>
          <Divider> Registration </Divider>
          {!registrationData && <Button
            onClick={createCredentialAction}
          >
            Register token
          </Button>}

          {registrationData && <Typography.Text>
            Registration data to be send to the server:<br /><br />
            <ul>
              <li>Token rawId: <Typography.Text code={true} ellipsis={true}>{toBase64(registrationData.rawId)}</Typography.Text></li>
              <li>Token available transports: {registrationData.transports.join(", ")}</li>
            </ul>
          </Typography.Text>}

          <Divider> Encrypt </Divider>
          <Space direction='vertical' style={{ width: "100%" }}>
            <Button
              onClick={prepareEncryptionKey}
              disabled={registrationData == null || encryptionKey != null}
            >
              Authorize key for encryption
            </Button>

            <Input
              disabled={encryptionKey == null}
              onChange={(e) => setToEncrypt(e.target.value)}
              onPressEnter={encryptAction}
            />
            <Button
              onClick={encryptAction}
              disabled={encryptionKey == null}
            >
              Encrypt!
            </Button>
          </Space>

          <Divider> Decrypt </Divider>
          <Space direction='vertical' style={{ width: "100%" }}>
            <Button
              onClick={prepareDecryptionKey}
              disabled={encryptionKey == null || decryptionKey != null}
            >
              Authorize key for decryption
            </Button>
            <Input
              disabled={decryptionKey == null}
              onChange={(e) => setToDecrypt(e.target.value)}
              onPressEnter={decryptAction}
            />
            <Button
              onClick={decryptAction}
              disabled={decryptionKey == null}
            >
              Decrypt!
            </Button>
          </Space>

        </Card>
        <Card title="Actions log" style={{ width: "500px", height: "fit-content" }}>
          <Timeline
            items={actionsLog.map((action) => {
              return {
                children: action.msg,
                dot: action.complete ? null : <Spin indicator={<LoadingOutlined style={{ fontSize: 18 }} spin />} />
              }
            })}
          />
        </Card>
      </Flex>
    </>
  );
}

export default App;
