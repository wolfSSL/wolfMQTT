#include <wolfMQTT.h>
#include <Ethernet.h>


/* Configuration */
#define DEFAULT_MQTT_HOST       "iot.eclipse.org" /* broker.hivemq.com */
#define DEFAULT_CMD_TIMEOUT_MS  30000
#define DEFAULT_CON_TIMEOUT_MS  5000
#define DEFAULT_MQTT_QOS        MQTT_QOS_0
#define DEFAULT_KEEP_ALIVE_SEC  60
#define DEFAULT_CLIENT_ID       "WolfMQTTClient"
#define WOLFMQTT_TOPIC_NAME     "wolfMQTT/example/"
#define DEFAULT_TOPIC_NAME      WOLFMQTT_TOPIC_NAME"testTopic"

#define MAX_BUFFER_SIZE         1024
#define TEST_MESSAGE            "test"
#define TEST_TOPIC_COUNT        2

/* Local Variables */
#ifdef ENABLE_MQTT_TLS
static WOLFSSL_METHOD* mMethod = 0;
static WOLFSSL_CTX* mCtx       = 0;
static WOLFSSL* mSsl           = 0;
static const char* mTlsFile    = NULL;
#endif
static word16 mPort            = 0;
static const char* mHost       = "iot.eclipse.org";
static int mStopRead    = 0;

EthernetClient ethClient;

/* Private functions */
static int EthernetConnect(void *context, const char* host, word16 port, int timeout_ms) 
{
  int ret = 0;

  ret = ethClient.connect(host, port);

  return ret;
}

static int EthernetRead(void *context, byte* buf, int buf_len, int timeout_ms) 
{
  int recvd = 0;
  /* While data and buffer available */
  while (ethClient.available() > 0 && recvd < buf_len) {
    buf[recvd] = ethClient.read();
    recvd++;
  }

  return recvd;
}

static int EthernetWrite(void *context, const byte* buf, int buf_len, int timeout_ms) 
{
  int sent = 0;

  sent = ethClient.write(buf, buf_len);

  return sent;
}

static int EthernetDisconnect(void *context) 
{
  ethClient.stop();

  return 0;
}

#ifdef ENABLE_MQTT_TLS
static int mqttclient_tls_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
  char buffer[WOLFSSL_MAX_ERROR_SZ];

  printf("MQTT TLS Verify Callback: PreVerify %d, Error %d (%s)\n", preverify,
         store->error, wolfSSL_ERR_error_string(store->error, buffer));
  printf("  Subject's domain name is %s\n", store->domain);

  if (store->error != 0) {
    /* Allowing to continue */
    /* Should check certificate and return 0 if not okay */
    printf("  Allowing cert anyways");
  }

  return 1;
}

static int mqttclient_tls_cb(MqttClient* cli)
{
  int rc = WOLFSSL_FAILURE;
  
  cli->tls.ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
  if (cli->tls.ctx) {
    wolfSSL_CTX_set_verify(cli->tls.ctx, SSL_VERIFY_PEER, mqttclient_tls_verify_cb);

    /* default to success */
    rc = WOLFSSL_SUCCESS;

    if (mTlsFile) {
      /* Load CA certificate file */
      rc = wolfSSL_CTX_load_verify_locations(cli->tls.ctx, mTlsFile, 0);
    }
  }
  else {
#if 0
    /* Load CA using buffer */
    rc = wolfSSL_CTX_load_verify_buffer(cli->tls.ctx, caCertBuf,
                                        caCertSize, WOLFSSL_FILETYPE_PEM);
#endif
    rc = WOLFSSL_SUCCESS;
  }

  printf("MQTT TLS Setup (%d)\n", rc);

  return rc;
}
#endif /* ENABLE_MQTT_TLS */

#define MAX_PACKET_ID   ((1 << 16) - 1)
static int mPacketIdLast;
static word16 mqttclient_get_packetid(void)
{
  mPacketIdLast = (mPacketIdLast >= MAX_PACKET_ID) ?
                  1 : mPacketIdLast + 1;
  return (word16)mPacketIdLast;
}

#define PRINT_BUFFER_SIZE    80
static int mqttclient_message_cb(MqttClient *client, MqttMessage *msg,
                                 byte msg_new, byte msg_done)
{
  byte buf[PRINT_BUFFER_SIZE + 1];
  word32 len;

  (void)client; /* Supress un-used argument */

  if (msg_new) {
    /* Determine min size to dump */
    len = msg->topic_name_len;
    if (len > PRINT_BUFFER_SIZE) {
      len = PRINT_BUFFER_SIZE;
    }
    XMEMCPY(buf, msg->topic_name, len);
    buf[len] = '\0'; /* Make sure its null terminated */

    /* Print incoming message */
    Serial.print("MQTT Message: Topic ");
    Serial.println((char*)buf);
    Serial.print("Qos ");
    Serial.println(msg->qos);
    Serial.print("Len ");
    Serial.println(msg->total_len);
  }

  /* Print message payload */
  len = msg->buffer_len;
  if (len > PRINT_BUFFER_SIZE) {
    len = PRINT_BUFFER_SIZE;
  }
  XMEMCPY(buf, msg->buffer, len);
  buf[len] = '\0'; /* Make sure its null terminated */
  Serial.print("Payload: ");
  Serial.println((char*)buf);

  if (msg_done) {
    Serial.println("MQTT Message: Done");
  }

  /* Return negative to terminate publish processing */
  return MQTT_CODE_SUCCESS;
}

/* Public Functions */
void setup() {
  Serial.begin(9600);

  return;
}

void loop() {
  int rc;
  MqttClient client;
  EthernetClient ethClient;
  MqttNet net;
#ifdef ENABLE_MQTT_TLS
  int use_tls = 1;
#else
  int use_tls = 0;
#endif
  MqttQoS qos = DEFAULT_MQTT_QOS;
  byte clean_session = 1;
  word16 keep_alive_sec = 60;
  const char* client_id = "wolfMQTTClient";
  int enable_lwt = 0;
  const char* username = NULL;
  const char* password = NULL;
  byte tx_buf[MAX_BUFFER_SIZE];
  byte rx_buf[MAX_BUFFER_SIZE];
  MqttMsgCb msg_cb;

  Serial.print("MQTT Client: QoS ");
  Serial.println(qos);
  
  /* Setup network callbacks */
  net.connect = EthernetConnect;
  net.read = EthernetRead;
  net.write = EthernetWrite;
  net.disconnect = EthernetDisconnect;
  net.context = &ethClient;

  /* Init Mqtt Client */
  rc = MqttClient_Init(&client, &net, mqttclient_message_cb, tx_buf, MAX_BUFFER_SIZE,
                       rx_buf, MAX_BUFFER_SIZE, DEFAULT_CMD_TIMEOUT_MS);
  Serial.print("MQTT Init: ");
  Serial.print(MqttClient_ReturnCodeToString(rc));
  Serial.print(" ");
  Serial.println(rc);

  /* Connect to broker server socket */
  rc = MqttClient_NetConnect(&client, mHost, mPort,
                             DEFAULT_CON_TIMEOUT_MS, use_tls,
#ifdef ENABLE_MQTT_TLS
                             mqttclient_tls_cb
#else
                             NULL
#endif
                             );
  Serial.print("MQTT Socket Connect: ");
  Serial.print(MqttClient_ReturnCodeToString(rc));
  Serial.print(" ");
  Serial.println(rc);

  if (rc == 0) {
    /* Define connect parameters */
    MqttConnect connect;
    MqttMessage lwt_msg;
    memset(&connect, 0, sizeof(MqttConnect));
    connect.keep_alive_sec = keep_alive_sec;
    connect.clean_session = clean_session;
    connect.client_id = client_id;
    /* Last will and testament sent by broker to subscribers
        of topic when broker connection is lost */
    memset(&lwt_msg, 0, sizeof(lwt_msg));
    connect.lwt_msg = &lwt_msg;
    connect.enable_lwt = enable_lwt;
    if (enable_lwt) {
      /* Send client id in LWT payload */
      lwt_msg.qos = qos;
      lwt_msg.retain = 0;
      lwt_msg.topic_name = WOLFMQTT_TOPIC_NAME"lwttopic";
      lwt_msg.buffer = (byte*)DEFAULT_CLIENT_ID;
      lwt_msg.total_len = (word16)strlen(DEFAULT_CLIENT_ID);
    }
    /* Optional authentication */
    connect.username = username;
    connect.password = password;

    /* Send Connect and wait for Connect Ack */
    rc = MqttClient_Connect(&client, &connect);
    printf("MQTT Connect: %s (%d)\n",
           MqttClient_ReturnCodeToString(rc), rc);
    if (rc == MQTT_CODE_SUCCESS) {
      MqttSubscribe subscribe;
      MqttUnsubscribe unsubscribe;
      MqttTopic topics[1], *topic;
      MqttPublish publish;
      int i;

      /* Build list of topics */
      topics[0].topic_filter = DEFAULT_TOPIC_NAME;
      topics[0].qos = qos;

      /* Validate Connect Ack info */
      Serial.print("MQTT Connect Ack: Return Code ");
      Serial.print(connect.ack.return_code);
      Serial.print(", Session Present ");
      Serial.println((connect.ack.flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) ? 1 : 0);

      /* Subscribe Topic */
      memset(&subscribe, 0, sizeof(MqttSubscribe));
      subscribe.packet_id = mqttclient_get_packetid();
      subscribe.topic_count = sizeof(topics)/sizeof(MqttTopic);
      subscribe.topics = topics;
      rc = MqttClient_Subscribe(&client, &subscribe);
      Serial.print("MQTT Subscribe: ");
      Serial.print(MqttClient_ReturnCodeToString(rc));
      Serial.print(" ");
      Serial.println(rc);
      for (i = 0; i < subscribe.topic_count; i++) {
        topic = &subscribe.topics[i];
        Serial.print("  Topic ");
        Serial.print(topic->topic_filter);
        Serial.print(" Qos ");
        Serial.print(topic->qos);
        Serial.print(" Return Code ");
        Serial.println(topic->return_code);
      }

      /* Publish Topic */
      memset(&publish, 0, sizeof(MqttPublish));
      publish.retain = 0;
      publish.qos = qos;
      publish.duplicate = 0;
      publish.topic_name = DEFAULT_TOPIC_NAME;
      publish.packet_id = mqttclient_get_packetid();
      publish.buffer = (byte*)TEST_MESSAGE;
      publish.total_len = (word16)strlen(TEST_MESSAGE);
      rc = MqttClient_Publish(&client, &publish);
      Serial.print("MQTT Publish: Topic ");
      Serial.print(publish.topic_name);
      Serial.print(", ");
      Serial.print(MqttClient_ReturnCodeToString(rc));
      Serial.print(", ");
      Serial.println(rc);

      /* Read Loop */
      Serial.println("MQTT Waiting for message...");
      while (mStopRead == 0) {
        /* Try and read packet */
        rc = MqttClient_WaitMessage(&client, DEFAULT_CMD_TIMEOUT_MS);
        if (rc != MQTT_CODE_SUCCESS && rc != MQTT_CODE_ERROR_TIMEOUT) {
          /* There was an error */
          Serial.print("MQTT Message Wait: ");
          Serial.print(MqttClient_ReturnCodeToString(rc));
          Serial.print(" ");
          Serial.println(rc);
          break;
        }

        /* Keep Alive */
        rc = MqttClient_Ping(&client);
        if (rc != MQTT_CODE_SUCCESS) {
            Serial.print("MQTT Ping: ");
            Serial.print(MqttClient_ReturnCodeToString(rc));
            Serial.print(" ");
            Serial.println(rc);
            break;
        }
      }

      /* Unsubscribe Topics */
      memset(&unsubscribe, 0, sizeof(MqttUnsubscribe));
      unsubscribe.packet_id = mqttclient_get_packetid();
      unsubscribe.topic_count = sizeof(topics)/sizeof(MqttTopic);
      unsubscribe.topics = topics;
      rc = MqttClient_Unsubscribe(&client, &unsubscribe);
      Serial.print("MQTT Unsubscribe: ");
      Serial.print(MqttClient_ReturnCodeToString(rc));
      Serial.print(" ");
      Serial.println(rc);

      /* Disconnect */
      rc = MqttClient_Disconnect(&client);
      Serial.print("MQTT Disconnect: ");
      Serial.print(MqttClient_ReturnCodeToString(rc));
      Serial.print(" ");
      Serial.println(rc);
    }

    rc = MqttClient_NetDisconnect(&client);
    Serial.print("MQTT Socket Disconnect: ");
    Serial.print(MqttClient_ReturnCodeToString(rc));
    Serial.print(" ");
    Serial.println(rc);
  }
}

