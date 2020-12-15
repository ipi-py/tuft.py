import typing
from pathlib import Path, PurePath

import requests
from requests_file import FileAdapter
from tuf.ngclient import Updater
from tuf.ngclient._internal.requests_fetcher import RequestsFetcher

from .serializer import jsonFancySerializer


class RequestsFetcherWithFile(RequestsFetcher):
	def __init__(self) -> None:
		super().__init__()
		self.fileAdapter = FileAdapter()

	def _get_session(self, url: str) -> requests.Session:
		s = super()._get_session(url)
		s.mount("file://", self.fileAdapter)
		return s


class Repo:
	__slots__ = ("localPath", "localMetadata", "updater")

	SETTINGS_SERIALIZER = jsonFancySerializer
	META_SERIALIZER = jsonFancySerializer

	@classmethod
	def setup(cls, reposRoot: Path, rootDict: dict, petname: str, baseURIs: typing.Optional[typing.Iterable[str]] = None) -> typing.Dict[str, typing.List[str]]:
		localPath = reposRoot / petname
		metaDir = cls.metaDirFromLocalPath(localPath)
		rootFilePath = cls.rootFilePathFromMetaDir(metaDir)
		rootFilePath.write_text(cls.META_SERIALIZER.unprocess(rootDict))

		localMetaFilePath = cls.localMetaFilePathFromReposRoot(localPath)
		localMetaDict = {"baseURIs": []}  # type: typing.Dict[str, typing.Any]
		if baseURIs:
			localMetaDict["baseURIs"].extend(baseURIs)
		localMetaFilePath.write_text(cls.SETTINGS_SERIALIZER.unprocess(localMetaDict))
		return localMetaDict

	LOCAL_META_FILE_NAME = "local"

	@classmethod
	def localMetaFilePathFromReposRoot(cls, localPath: Path) -> Path:
		return localPath / (cls.LOCAL_META_FILE_NAME + "." + cls.SETTINGS_SERIALIZER.fileExtension)

	ROOT_FILE_NAME = "root"

	@classmethod
	def rootFilePathFromMetaDir(cls, metaDir: Path) -> Path:
		return metaDir / (cls.ROOT_FILE_NAME + "." + cls.META_SERIALIZER.fileExtension)

	@classmethod
	def metaDirFromLocalPath(cls, localPath: Path) -> Path:
		res = localPath / "meta"
		res.mkdir(exist_ok=True, parents=True)
		return res

	@classmethod
	def repoDirFromLocalPath(cls, localPath: Path) -> Path:
		res = localPath / "repo"
		res.mkdir(exist_ok=True, parents=True)
		return res

	def __init__(self, localPath: Path, localMetadata: typing.Optional[dict] = None) -> None:
		if localMetadata is None:
			localMetadata = {}

		self.localPath = localPath
		self.localMetadata = localMetadata
		self.refreshLocalMetadata()
		self.updater = typing.cast(Updater, None)
		self.initTUF()

	@property
	def baseURI(self) -> str:
		return self.baseURIs[0]

	@property
	def baseURIs(self) -> typing.List[str]:
		return self.localMetadata["baseURIs"]

	def initTUF(self) -> None:
		self.updater = Updater(metadata_dir=str(self.__class__.metaDirFromLocalPath(self.localPath)), metadata_base_url=self.baseURI, target_base_url=self.baseURI, target_dir=str(self.__class__.repoDirFromLocalPath(self.localPath)), fetcher=RequestsFetcherWithFile())

	def refreshLocalMetadata(self) -> None:
		localMetaFile = self.__class__.localMetaFilePathFromReposRoot(self.localPath)
		self.localMetadata = self.__class__.SETTINGS_SERIALIZER.process(localMetaFile.read_text())

	def update(self) -> None:
		self.updater.refresh()

	def getListPath(self, path: PurePath) -> Path:
		info = self.updater.get_targetinfo(str(path))

		if info:
			cached = self.updater.find_cached_target(info)
			if not cached:
				self.updater.download_target(info)
				cached = self.updater.find_cached_target(info)

			if not cached:
				raise KeyError(path)

			return Path(cached)

		raise KeyError(path)

	def __iter__(self) -> typing.Iterable[PurePath]:
		for fns in self.updater._trusted_set.targets.signed.targets:
			fn = PurePath(fns)
			yield fn

	def __getitem__(self, k: PurePath) -> Path:
		return self.getListPath(k)
