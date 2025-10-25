"""
Kafka producer and consumer helpers using aiokafka.
Provides async utilities for message streaming.
"""

import asyncio
import json
from typing import AsyncIterator, Optional, Callable, Any
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import TopicAlreadyExistsError
from loguru import logger
from pydantic import BaseModel


class KafkaProducerHelper:
    """Async Kafka producer with JSON serialization."""
    
    def __init__(self, bootstrap_servers: str):
        self.bootstrap_servers = bootstrap_servers
        self.producer: Optional[AIOKafkaProducer] = None
    
    async def start(self):
        """Initialize and start the producer."""
        self.producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            key_serializer=lambda k: k.encode('utf-8') if k else None,
        )
        await self.producer.start()
        #logger.info(f"Kafka producer started: {self.bootstrap_servers}")
    
    async def stop(self):
        """Stop the producer."""
        if self.producer:
            await self.producer.stop()
            logger.info("Kafka producer stopped")
    
    async def send(self, topic: str, message: BaseModel | dict, key: Optional[str] = None):
        """Send a message to a topic."""
        if not self.producer:
            raise RuntimeError("Producer not started")
        
        if isinstance(message, BaseModel):
            value = json.loads(message.model_dump_json())
        else:
            value = message
        
        await self.producer.send(topic, value=value, key=key)
        logger.debug(f"Sent to {topic}: {value}")


class KafkaConsumerHelper:
    """Async Kafka consumer with JSON deserialization."""
    
    def __init__(
        self,
        bootstrap_servers: str,
        topics: list[str],
        group_id: str,
        auto_offset_reset: str = "latest"
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topics = topics
        self.group_id = group_id
        self.auto_offset_reset = auto_offset_reset
        self.consumer: Optional[AIOKafkaConsumer] = None
    
    async def start(self):
        """Initialize and start the consumer."""
        self.consumer = AIOKafkaConsumer(
            *self.topics,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            auto_offset_reset=self.auto_offset_reset,
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            key_deserializer=lambda k: k.decode('utf-8') if k else None,
        )
        await self.consumer.start()
        #logger.info(f"Kafka consumer started: topics={self.topics}, group={self.group_id}")
    
    async def stop(self):
        """Stop the consumer."""
        if self.consumer:
            await self.consumer.stop()
            logger.info("Kafka consumer stopped")
    
    async def consume(self) -> AsyncIterator[dict]:
        """Consume messages from subscribed topics."""
        if not self.consumer:
            raise RuntimeError("Consumer not started")
        
        async for msg in self.consumer:
            logger.debug(f"Received from {msg.topic}: {msg.value}")
            yield {
                "topic": msg.topic,
                "key": msg.key,
                "value": msg.value,
                "partition": msg.partition,
                "offset": msg.offset,
            }


async def ensure_topics(bootstrap_servers: str, topics: list[str], num_partitions: int = 1):
    """Ensure Kafka topics exist, creating them if necessary."""
    admin = AIOKafkaAdminClient(bootstrap_servers=bootstrap_servers)
    await admin.start()
    
    try:
        new_topics = [
            NewTopic(name=topic, num_partitions=num_partitions, replication_factor=1)
            for topic in topics
        ]
        await admin.create_topics(new_topics, validate_only=False)
        #logger.info(f"Created topics: {topics}")
    except TopicAlreadyExistsError:
        logger.debug(f"Topics already exist: {topics}")
    except Exception as e:
        logger.warning(f"Error ensuring topics: {e}")
    finally:
        await admin.close()
