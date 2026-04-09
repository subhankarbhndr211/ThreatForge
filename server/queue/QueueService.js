/**
 * ThreatForge Message Queue Service
 * Supports Kafka and RabbitMQ for async packet processing
 */

const { EventEmitter } = require('events');

class QueueService extends EventEmitter {
    constructor() {
        super();
        this.type = null;
        this.connection = null;
        this.producers = new Map();
        this.consumers = new Map();
        this.messageBuffer = [];
        this.config = {
            kafka: {
                brokers: process.env.KAFKA_BROKERS?.split(',') || ['localhost:9092'],
                clientId: 'threatforge-packet-analyzer',
                groupId: 'threatforge-analyzers'
            },
            rabbitmq: {
                url: process.env.RABBITMQ_URL || 'amqp://localhost',
                vhost: process.env.RABBITMQ_VHOST || '/'
            },
            redis: {
                host: process.env.REDIS_HOST || 'localhost',
                port: parseInt(process.env.REDIS_PORT) || 6379,
                password: process.env.REDIS_PASSWORD || undefined
            }
        };
    }

    async connect(type = 'kafka') {
        this.type = type;

        if (type === 'kafka') {
            return this.connectKafka();
        } else if (type === 'rabbitmq') {
            return this.connectRabbitMQ();
        } else if (type === 'redis') {
            return this.connectRedis();
        } else {
            throw new Error(`Unsupported queue type: ${type}`);
        }
    }

    async connectKafka() {
        try {
            const { Kafka } = require('kafkajs');
            const kafka = new Kafka(this.config.kafka);
            
            this.connection = {
                kafka,
                producer: kafka.producer(),
                consumer: kafka.consumer({ groupId: this.config.kafka.groupId }),
                admin: kafka.admin()
            };

            await this.connection.producer.connect();
            await this.connection.consumer.connect();
            
            console.log('[Queue] Kafka connected successfully');
            this.emit('connected', 'kafka');
            return true;
        } catch (err) {
            console.warn('[Queue] Kafka connection failed, using fallback mode:', err.message);
            this.type = 'memory';
            return false;
        }
    }

    async connectRabbitMQ() {
        try {
            const amqp = require('amqplib');
            this.connection = await amqp.connect(this.config.rabbitmq.url);
            
            this.connection.channel = await this.connection.createChannel();
            await this.connection.channel.assertExchange('threatforge', 'topic', { durable: true });
            
            console.log('[Queue] RabbitMQ connected successfully');
            this.emit('connected', 'rabbitmq');
            return true;
        } catch (err) {
            console.warn('[Queue] RabbitMQ connection failed, using fallback mode:', err.message);
            this.type = 'memory';
            return false;
        }
    }

    async connectRedis() {
        try {
            const redis = require('redis');
            this.connection = redis.createClient({
                socket: {
                    host: this.config.redis.host,
                    port: this.config.redis.port
                },
                password: this.config.redis.password
            });

            this.connection.on('error', (err) => {
                console.error('[Queue] Redis error:', err.message);
            });

            await this.connection.connect();
            console.log('[Queue] Redis queue connected successfully');
            this.emit('connected', 'redis');
            return true;
        } catch (err) {
            console.warn('[Queue] Redis connection failed, using fallback mode:', err.message);
            this.type = 'memory';
            return false;
        }
    }

    async publish(topic, message) {
        const payload = {
            topic,
            message: typeof message === 'string' ? message : JSON.stringify(message),
            timestamp: Date.now()
        };

        if (this.type === 'kafka' && this.connection?.producer) {
            try {
                await this.connection.producer.send({
                    topic,
                    messages: [{ value: payload.message, key: payload.topic }]
                });
                this.emit('published', topic, payload);
                return true;
            } catch (err) {
                console.error('[Queue] Kafka publish error:', err.message);
            }
        } else if (this.type === 'rabbitmq' && this.connection?.channel) {
            try {
                this.connection.channel.publish('threatforge', topic, Buffer.from(payload.message));
                this.emit('published', topic, payload);
                return true;
            } catch (err) {
                console.error('[Queue] RabbitMQ publish error:', err.message);
            }
        } else if (this.type === 'redis' && this.connection) {
            try {
                await this.connection.lPush(`queue:${topic}`, payload.message);
                this.emit('published', topic, payload);
                return true;
            } catch (err) {
                console.error('[Queue] Redis publish error:', err.message);
            }
        }

        this.messageBuffer.push(payload);
        this.emit('published', topic, payload);
        return true;
    }

    async subscribe(topic, handler) {
        const consumerId = `${topic}-${Date.now()}`;

        if (this.type === 'kafka' && this.connection?.consumer) {
            await this.connection.consumer.subscribe({ topic, fromBeginning: false });
            await this.connection.consumer.run({
                eachMessage: async ({ topic, partition, message }) => {
                    handler({
                        topic,
                        partition,
                        offset: message.offset,
                        value: message.value.toString()
                    });
                }
            });
        } else if (this.type === 'rabbitmq' && this.connection?.channel) {
            const q = await this.connection.channel.assertQueue(consumerId, { exclusive: true });
            await this.connection.channel.bindQueue(q.queue, 'threatforge', topic);
            
            this.connection.channel.consume(q.queue, (msg) => {
                if (msg) {
                    handler({
                        topic,
                        value: msg.content.toString()
                    });
                    this.connection.channel.ack(msg);
                }
            });
        } else {
            this.consumers.set(topic, handler);
        }

        this.emit('subscribed', topic, consumerId);
        return consumerId;
    }

    async consume(topic) {
        if (this.type === 'redis' && this.connection) {
            const result = await this.connection.brPop(`queue:${topic}`, 5);
            return result ? JSON.parse(result.element) : null;
        }

        if (this.type === 'memory') {
            const idx = this.messageBuffer.findIndex(m => m.topic === topic);
            if (idx >= 0) {
                return JSON.parse(this.messageBuffer.splice(idx, 1)[0].message);
            }
        }

        return null;
    }

    async getQueueStats() {
        const stats = {
            type: this.type,
            connected: !!this.connection,
            topics: {
                published: new Set(),
                subscribed: new Set()
            },
                messageBufferSize: this.messageBuffer.length,
            producers: this.producers.size,
            consumers: this.consumers.size
        };

        return stats;
    }

    async disconnect() {
        if (this.connection) {
            if (this.type === 'kafka') {
                await this.connection.producer?.disconnect();
                await this.connection.consumer?.disconnect();
            } else if (this.type === 'rabbitmq') {
                await this.connection.channel?.close();
                await this.connection.close();
            } else if (this.type === 'redis') {
                await this.connection.quit();
            }
        }
        this.emit('disconnected', this.type);
        console.log('[Queue] Disconnected from', this.type);
    }
}

const queueService = new QueueService();

queueService.on('published', (topic, payload) => {
    console.log(`[Queue] Published to ${topic}`);
});

queueService.on('subscribed', (topic, consumerId) => {
    console.log(`[Queue] Subscribed to ${topic} as ${consumerId}`);
});

module.exports = { queueService, QueueService };
