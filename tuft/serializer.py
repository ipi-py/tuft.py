__all__ = ("jsonFancySerializer",)

import typing
from types import ModuleType

from tuf.api.metadata import Metadata
from tuf.api.serialization import DeserializationError, MetadataDeserializer, MetadataSerializer, SerializationError

try:
	from transformerz.serialization.json import FileTransformer, jsonFancySerializer
except ImportError:
	# a fallback impl
	# pylint:disable=too-few-public-methods

	class FileTransformer:
		__slots__ = ("id", "unprocess", "process", "fileExtension", "mimeType")

		def __init__(self, name: str, unprocess: typing.Callable[[typing.Dict[str, typing.Any]], str], process: typing.Callable[[str], typing.Any], srcType: type, tgtType: type, fileExtension: str, mimeType: typing.Optional[str] = None) -> None:  # pylint:disable=too-many-arguments,unused-argument
			self.id = name
			self.unprocess = unprocess
			self.process = process
			self.fileExtension = fileExtension
			self.mimeType = mimeType

	import json as jsonFancy

	json = jsonFancy  # type: ModuleType
	try:
		import ujson as json
	except ImportError:
		pass

	def fancyJSONSerialize(v: dict) -> str:
		return jsonFancy.dumps(v, indent="\t")

	jsonFancySerializer = FileTransformer("json", fancyJSONSerialize, json.loads, str, typing.Mapping[str, typing.Any], "json", "text/json")


class DeserializerWrapper(MetadataDeserializer):  # pylint:disable=too-few-public-methods
	__slots__ = ("deserializer",)

	def __init__(self, deserializer):
		self.deserializer = deserializer

	def deserialize(self, raw_data: bytes) -> Metadata:
		try:
			dic = self.deserializer.process(raw_data)
			return Metadata.from_dict(dic)

		except Exception as e:
			raise DeserializationError("Failed to deserialize") from e


class SerializerWrapper(MetadataSerializer):  # pylint:disable=too-few-public-methods
	__slots__ = ("serializer",)

	def __init__(self, serializer):
		self.serializer = serializer

	def serialize(self, metadata_obj: Metadata) -> bytes:
		try:
			dic = metadata_obj.to_dict()
			return self.serializer.unprocess(dic)

		except Exception as e:
			raise SerializationError("Failed to serialize") from e
