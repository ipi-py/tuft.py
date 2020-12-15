import re
import typing
from datetime import datetime, timedelta
from pathlib import Path

from securesystemslib.signer import SSlibSigner
from tuf.api.metadata import Key, Metadata, MetaFile, Root, Signed, Snapshot, TargetFile, Targets, Timestamp

from .serializer import FileTransformer, jsonFancySerializer

# pylint:disable=too-many-arguments


def _in(seconds: float) -> datetime:
	return datetime.utcnow().replace(microsecond=0) + timedelta(seconds=seconds)


class Storeable:  # pylint:disable=too-few-public-methods
	__slots__ = ()

	def save(self, repoRoot: Path):
		raise NotImplementedError


class Signable:  # pylint:disable=too-few-public-methods
	__slots__ = ()

	def sign(self, key) -> bool:
		raise NotImplementedError

	@property
	def needsSigning(self) -> bool:
		raise NotImplementedError


class RoleFactory:  # pylint:disable=too-few-public-methods
	__slots__ = ("name", "ctor", "defaultExpire", "deps", "hasVersion")

	def __init__(self, name: str, ctor: typing.Type[Signed], defaultExpire: int, deps: typing.Tuple["RoleFactory", ...], hasVersion: bool = True) -> None:
		self.name = name
		self.ctor = ctor
		self.defaultExpire = defaultExpire
		self.deps = deps
		self.hasVersion = hasVersion

	def fromDict(self, roleClass: typing.Type["OurRole"], dic: dict) -> "OurRole":
		return roleClass(self, Metadata[self.ctor].from_dict(dic))

	def createEmpty(self, roleClass: typing.Type["OurRole"], **kwargs) -> "OurRole":
		res = roleClass(self, Metadata(self.ctor(expires=_in(self.defaultExpire), **kwargs)))
		res._version = 0  # illegal, but will be increased automatically into the legal range when signing
		return res

	def __repr__(self) -> str:
		return self.__class__.__name__ + "(" + ", ".join(repr(getattr(self, k)) for k in self.__class__.__slots__) + ")"


FileNameDiscoveredMetadataSimpleVersionT = typing.Tuple[None, str]
FileNameDiscoveredMetadataConsistentVersionT = typing.Tuple[int, str]
FileNameDiscoveredMetadataVersionT = typing.Union[FileNameDiscoveredMetadataSimpleVersionT, FileNameDiscoveredMetadataConsistentVersionT]
FileNameDiscoveredUserFileVersionT = typing.Tuple[typing.Optional[str], str]


class OurRoleLayout:
	@classmethod
	def getConsistentFileName(cls, ext, roleName, version):
		return str(version) + "." + roleName + "." + ext

	@classmethod
	def getSimpleFileName(cls, ext: str, roleName: str) -> str:
		return roleName + "." + ext

	@classmethod
	def getFileName(cls, ext: str, roleFactory: RoleFactory, roleVersion: typing.Union[int, str], isConsistent: bool) -> str:
		if isConsistent:
			fn = cls.getConsistentFileName(ext, roleFactory.name, str(roleVersion))
		else:
			fn = cls.getSimpleFileName(ext, roleFactory.name)
		return fn

	@classmethod
	def discoverBlindFromRepo(cls, ext: str, roleFactory: RoleFactory, repoRoot: Path, isConsistent: bool) -> typing.Tuple[None, Path]:
		assert "*" not in roleFactory.name
		if isConsistent:
			return cls.discoverConsistent(ext, roleFactory, repoRoot)

		return cls.discoverSimple(ext, roleFactory, repoRoot)

	@classmethod
	def discoverSimple(cls, ext: str, roleFactory: RoleFactory, repoRoot: Path) -> typing.Tuple[None, Path]:
		return None, repoRoot / cls.getSimpleFileName(ext, roleFactory.name)

	@classmethod
	def discoverConsistent(cls, ext, roleFactory: RoleFactory, repoRoot: Path):
		versions = cls.discoverConsistentVersionsFromFileNames(ext, roleFactory, cls.discoverFilesInRepoRoot(repoRoot))
		version, fileName = versions[-1]
		return version, repoRoot / fileName

	@classmethod
	def discoverFilesInRepoRoot(cls, repoRoot: Path):
		for p in repoRoot.iterdir():
			if p.is_file():
				yield p.name

	@classmethod
	def discoverVersionsFromFileNames(cls, ext: str, roleFactory: RoleFactory, fileNames: typing.Iterable[str], isConsistent: bool) -> typing.Collection[FileNameDiscoveredMetadataVersionT]:
		assert "*" not in roleFactory.name
		if isConsistent:
			return cls.discoverConsistentVersionsFromFileNames(ext, roleFactory, fileNames)

		return cls.discoverSipleVersionsFromFileNames(ext, roleFactory, fileNames)

	@classmethod
	def discoverSipleVersionsFromFileNames(cls, ext: str, roleFactory: RoleFactory, fileNames: typing.Iterable[str]) -> typing.List[FileNameDiscoveredMetadataSimpleVersionT]:
		simpleFileName = cls.getSimpleFileName(ext, roleFactory.name)
		if simpleFileName in set(fileNames):
			return [(None, simpleFileName)]

		return []

	@classmethod
	def discoverConsistentVersionsFromFileNames(cls, ext, roleFactory: RoleFactory, fileNames: typing.Iterable[str]) -> typing.List[FileNameDiscoveredMetadataConsistentVersionT]:
		assert "*" not in roleFactory.name
		roleGlobFnRegExp = re.compile(cls.getConsistentFileName(ext, roleFactory.name, "(\\d+)").replace(".", "\\."))
		versions = []
		for fn in fileNames:
			m = roleGlobFnRegExp.match(fn)
			if m:
				version = m.group(1)
				try:
					version = int(version)
				except ValueError:
					continue
			else:
				continue
			versions.append((version, fn))
		versions = sorted(versions, key=lambda x: x[0])

		if not versions:
			raise FileNotFoundError(roleGlobFnRegExp.pattern)

		return versions


class RolePersister:
	__slots__ = ("serializer", "layout")

	def __init__(self, serializer: FileTransformer, layout: typing.Type[OurRoleLayout]) -> None:
		self.serializer = serializer
		self.layout = layout

	def getFileName(self, roleFactory: RoleFactory, roleVersion: typing.Union[int, str], isConsistent: bool) -> str:
		return self.layout.getFileName(self.serializer.fileExtension, roleFactory, roleVersion, isConsistent)

	def _save(self, repoRoot: Path, isConsistent: bool, role: "OurRole") -> None:
		(repoRoot / self.getFileName(role.fac, role.version, isConsistent)).write_text(self.serializer.unprocess(role.role.to_dict()))

	def save(self, repoRoot: Path, isConsistent: bool, role: "OurRole") -> None:
		if role.needsSaving:
			if role.needsSigning:
				raise RuntimeError("The data for the role is unsigned!", role.name)

			self._save(repoRoot, isConsistent, role)
			role.needsSaving = False

	def discoverVersionsFromFileNames(self, roleFactory: RoleFactory, fileNames: typing.Iterable[str], isConsistent: bool) -> typing.List[FileNameDiscoveredMetadataVersionT]:
		return self.layout.discoverVersionsFromFileNames(self.serializer.fileExtension, roleFactory, fileNames, isConsistent)

	def loadFromRepo(self, roleFactory: RoleFactory, roleClass: typing.Type["OurRole"], repoRoot: Path, isConsistent: bool, versionToLoad: typing.Optional[typing.Union[int, str]]) -> "OurRole":
		versionToCheck = None
		if versionToLoad is None:
			fileNameVersion, filePath = self.layout.discoverBlindFromRepo(self.serializer.fileExtension, roleFactory, repoRoot, isConsistent)
			if isConsistent:
				versionToCheck = fileNameVersion
		else:
			filePath = repoRoot / self.getFileName(roleFactory, versionToLoad, isConsistent)
			versionToCheck = versionToLoad

		loaded = self.loadFromFile(roleFactory, roleClass, filePath, versionToCheck)
		# ToDo: '_type': 'targets'
		return loaded

	def loadFromFile(self, roleFactory: RoleFactory, roleClass: typing.Type["OurRole"], path: Path, expectedVersion: typing.Optional[typing.Union[int, str]] = None) -> "OurRole":
		return self.loadFromData(roleFactory, roleClass, path.read_bytes(), expectedVersion)

	def deserializeData(self, data: typing.Union[bytes, str]) -> dict:
		if isinstance(data, bytes):
			data = data.decode("utf-8")

		if isinstance(data, str):
			data = self.serializer.process(data)

		if not isinstance(data, dict):
			raise ValueError("Incorrect data")
		return data

	def loadFromData(self, roleFactory: RoleFactory, roleClass: typing.Type["OurRole"], data: typing.Union[bytes, str], expectedVersion: typing.Optional[typing.Union[int, str]] = None) -> "OurRole":
		loaded = roleFactory.fromDict(roleClass, self.deserializeData(data))
		if expectedVersion is not None and loaded.version != expectedVersion:
			raise RuntimeError("Version within file doesn't match the expected version", roleFactory.name, expectedVersion, loaded.version)

		return loaded

	def loadOrCreate(self, roleFactory: RoleFactory, roleClass: typing.Type["OurRole"], repoRoot: typing.Optional[Path], isConsistent: bool, versionToLoad: typing.Optional[typing.Union[int, str]] = None, **kwargs) -> typing.Tuple["OurRole", bool]:
		if repoRoot is not None:
			try:
				return self.loadFromRepo(roleFactory, roleClass, repoRoot, isConsistent, versionToLoad), True
			except FileNotFoundError:
				return roleFactory.createEmpty(roleClass, **kwargs), False

		return roleClass.createEmpty(roleFactory, **kwargs), False


class OurRole(Signable):
	"""Our class for a role because TUF doesn't provide one"""

	__slots__ = ("fac", "role", "_needsSigning", "_needsSaving")

	def __init__(self, fac: RoleFactory, role: Metadata) -> None:
		assert isinstance(fac, RoleFactory)
		self.role = role
		self.fac = fac
		self._needsSigning = False
		self._needsSaving = False

	def __repr__(self) -> str:
		return self.__class__.__name__ + "(" + Metadata.__name__ + "(" + repr(dict(self.role.signed.to_dict())) + "), " + ", ".join(repr(el) for el in (self.name,)) + ")"

	@property
	def name(self) -> str:
		return self.fac.name

	@property
	def needsSigning(self) -> bool:
		return self._needsSigning

	@needsSigning.setter
	def needsSigning(self, v: bool):
		if self._needsSigning != v:
			self._needsSaving = True
			self._needsSigning = v

	@property
	def needsSaving(self) -> bool:
		return self._needsSaving

	@needsSaving.setter
	def needsSaving(self, v: bool):
		self._needsSaving = v

	@classmethod
	def createEmpty(cls, roleFactory: RoleFactory, **kwargs) -> "OurRole":
		return roleFactory.createEmpty(cls, **kwargs)

	@property
	def version(self):
		return self._version

	@version.setter
	def version(self, v):
		if v < self.version:
			raise ValueError("Version decrease", self.version, v)
		if v != self.version:
			self._version = v

	@property
	def _version(self):
		return self.role.signed.version

	@_version.setter
	def _version(self, v):
		self.role.signed.version = v
		self.needsSigning = True

	def bumpVersion(self) -> None:
		self._version = self.version + 1

	def sign(self, key) -> bool:
		if self.needsSigning:
			self.bumpVersion()
			signer = SSlibSigner(key)
			self.role.sign(signer)
			self.needsSigning = False
			self.needsSaving = True
			return True
		return False


class KeyManager:
	__slots__ = ("_keys",)

	def __init__(self, keys) -> None:
		for rN in keys:
			keys[rN] = keys[rN]

		self._keys = keys

	def __iter__(self):
		return iter(self._keys.items())

	def __getitem__(self, k: str):
		return self._keys[k]

	def __setitem__(self, k, v):
		self._keys[k] = v

	def __contains__(self, k):
		return k in self._keys[k]

	def __len__(self):
		return len(self._keys)

	def items(self):
		return self._keys.items()

	def roles(self):
		return self._keys.keys()

	def sign(self, oR: OurRole) -> bool:
		return oR.sign(self._keys[oR.name])

	@classmethod
	def fromSingleKey(cls, key, roleNames: typing.Iterable[str]) -> "KeyManager":
		"""Generates a key manager with all the role keys that are the same"""

		return cls({rn: key for rn in roleNames})


rootRoleFac = RoleFactory("root", Root, 365 * 24 * 3600, (), False)
targetsRoleFac = RoleFactory("targets", Targets, 7 * 24 * 3600, (rootRoleFac,))
snapshotRoleFac = RoleFactory("snapshot", Snapshot, 7 * 24 * 3600, (targetsRoleFac,))
timestampRoleFac = RoleFactory("timestamp", Timestamp, 7 * 24 * 3600, (snapshotRoleFac,), False)


class RolesModel(dict):
	ROOT_ROLE_FAC = rootRoleFac

	def __init__(self, roleCtors: typing.Union[typing.Dict[str, RoleFactory], typing.Iterable[RoleFactory]]) -> None:
		if not isinstance(roleCtors, dict):
			roleCtors = {el.name: el for el in roleCtors}

		super().__init__(roleCtors)

	def keyManagerFromSingleKey(self, rolesKey) -> KeyManager:
		"""Generates a key manager with all the role keys that are the same"""

		return KeyManager.fromSingleKey(rolesKey, (self.__class__.ROOT_ROLE_FAC.name,) + tuple(self))


ROLES_MODEL = RolesModel((targetsRoleFac, snapshotRoleFac, timestampRoleFac))  # Order matters!


class RolesStrategy:
	__slots__ = ("roleClass", "persister", "model")

	def __init__(self, roleClass: typing.Type["OurRole"], persister: RolePersister, model: RolesModel) -> None:
		self.roleClass = roleClass
		self.persister = persister
		self.model = model

	def isRoleConsistent(self, roleFactory: RoleFactory, isConsistent: bool) -> bool:
		return isConsistent and roleFactory.hasVersion

	def fileNameForRole(self, roleFactory: RoleFactory, roleVersion: typing.Union[int, str], isConsistent: bool) -> str:
		return self.persister.getFileName(roleFactory, roleVersion, self.isRoleConsistent(roleFactory, isConsistent))

	def loadOrCreate(self, roleFactory: RoleFactory, repoRoot: typing.Optional[Path], isConsistent: bool, versionToLoad: typing.Optional[typing.Union[int, str]] = None, **kwargs) -> typing.Tuple[OurRole, bool]:
		return self.persister.loadOrCreate(roleFactory, self.roleClass, repoRoot, self.isRoleConsistent(roleFactory, isConsistent), versionToLoad, **kwargs)

	def save(self, repoRoot: Path, isConsistent: bool, role: "OurRole") -> None:
		return self.persister.save(repoRoot, self.isRoleConsistent(role.fac, isConsistent), role)

	def createEmptyRoot(self, consistent: bool) -> OurRole:
		root = self.roleClass.createEmpty(self.model.ROOT_ROLE_FAC, consistent_snapshot=consistent)
		return root

	def loadFromFile(self, roleFactory: RoleFactory, path: Path, expectedVersion: typing.Optional[typing.Union[int, str]] = None) -> OurRole:
		return self.persister.loadFromFile(roleFactory, self.roleClass, path, expectedVersion)

	def loadFromData(self, roleFactory: RoleFactory, data: typing.Union[bytes, str], expectedVersion: typing.Optional[typing.Union[int, str]] = None):
		return self.persister.loadFromData(roleFactory, self.roleClass, data, expectedVersion)

	def loadRoot(self, data: typing.Union[Path, bytes, str, dict]) -> OurRole:
		if isinstance(data, Path):
			if data.is_dir():
				nonConsistentName = self.fileNameForRole(self.model.ROOT_ROLE_FAC, 0, False)
				nonConsistentCand = data / nonConsistentName
				if nonConsistentCand.is_file():
					data = nonConsistentCand
				else:
					consistentCands = list(data.glob("*." + nonConsistentName))
					if len(consistentCands) > 1:
						raise ValueError("More than one consistent cand in dir, refuse to guess")

					data = consistentCands[0]

			return self.loadFromFile(self.model.__class__.ROOT_ROLE_FAC, typing.cast(Path, data))

		if isinstance(data, (bytes, str)):
			return self.loadFromData(self.model.__class__.ROOT_ROLE_FAC, data)

		raise TypeError("`data` is of wrong type", type(data))

	def loadDumb(self, repoRoot: typing.Optional[Path], isConsistent: bool):
		rolesDict = {}
		for fac in self.model.values():
			rolesDict[fac.name], _isLoaded = self.loadOrCreate(fac, repoRoot, isConsistent)
		return rolesDict

	def loadOrCreateRoles(self, repoRoot: typing.Optional[Path], isConsistent: bool) -> typing.Dict[str, OurRole]:
		rolesDict = {}
		rolesDict["timestamp"], _isLoaded = self.loadOrCreate(self.model["timestamp"], repoRoot, False, None)
		rolesDict["snapshot"], isSnapshotLoaded = self.loadOrCreate(self.model["snapshot"], repoRoot, False, rolesDict["timestamp"].role.signed.snapshot_meta.version)

		if not isSnapshotLoaded:
			# Shit, bullshit files are added automatically even if don't exist!
			rolesDict["snapshot"].role.signed.meta.clear()

		rolesToLoad = set(self.model) - set(rolesDict)

		signedMetadataFiles = rolesDict["snapshot"].role.signed.meta

		for rn in sorted(rolesToLoad):
			fac = self.model[rn]
			versionsFromFileNames = self.persister.discoverVersionsFromFileNames(fac, signedMetadataFiles, self.isRoleConsistent(fac, isConsistent))

			if len(versionsFromFileNames) != 0:
				if len(versionsFromFileNames) > 1:
					raise RuntimeError("Not unique metadata file for a role", fac, versionsFromFileNames)

				expectedVersionFromFileName, fileName = versionsFromFileNames[0]
				expectedVersion = signedMetadataFiles[fileName].version

				if expectedVersionFromFileName is not None and expectedVersion != expectedVersionFromFileName:
					raise ValueError("Expected version from file name doesn't math the one from metadata", fileName, expectedVersionFromFileName, expectedVersion)

				filePath = repoRoot / fileName
				rolesDict[fac.name] = self.loadFromFile(fac, filePath, expectedVersion)
			else:
				rolesDict[fac.name] = self.roleClass.createEmpty(fac)

			rolesToLoad -= {fac.name}

		if rolesToLoad:
			raise RuntimeError("Not all roles have been loaded from the required ones", rolesToLoad)

		return rolesDict


FS_DETACHED_NOTICE = """
This entity is usually detached from filesystem
Loading from a FS is done with `load` clasmethod.
To save use `save` method.
"""


def _collectParentRoles(curRole: RoleFactory) -> typing.List[RoleFactory]:
	res = []

	for depRole in curRole.deps:
		res.append(depRole)
		res.extend(_collectParentRoles(depRole))

	return res


class RepoSeed(Storeable):
	"""The root aspects of a repo operation
	* roles
	* keys
	* whether consistent or not
	* mapping roles to file names
	"""

	__slots__ = ("keys", "root", "rootKey", "rolesKey")

	STRATEGY = RolesStrategy(OurRole, RolePersister(jsonFancySerializer, OurRoleLayout), ROLES_MODEL)

	@classmethod
	def keyManagerFromSingleKey(cls, rolesKey) -> KeyManager:
		return cls.STRATEGY.model.keyManagerFromSingleKey(rolesKey)

	keyManagerFromSingleKey.__doc__ = RolesModel.keyManagerFromSingleKey.__doc__

	def __init__(self, root: OurRole, keys: typing.Union[dict, KeyManager]) -> None:
		if isinstance(keys, dict):
			keys = KeyManager(keys)

		self.keys = keys
		self.root = root

	@classmethod
	def make(cls, keys: typing.Union[dict, KeyManager], consistent: bool = False, allowParentKeys: bool = True) -> "RepoSeed":
		if isinstance(keys, dict):
			keys = KeyManager(keys)

		root = cls.STRATEGY.createEmptyRoot(consistent)

		rootKeyObject = keys[cls.STRATEGY.model.ROOT_ROLE_FAC.name]
		root.role.signed.add_key(Key.from_securesystemslib_key(rootKeyObject), cls.STRATEGY.model.ROOT_ROLE_FAC.name)

		for roleFac in cls.STRATEGY.model.values():
			root.role.signed.add_key(Key.from_securesystemslib_key(keys[roleFac.name]), roleFac.name)

			if allowParentKeys:
				for depRole in _collectParentRoles(roleFac):
					root.role.signed.add_key(Key.from_securesystemslib_key(keys[depRole.name]), roleFac.name)

		res = cls(root, keys)
		res.sign()

		return res

	@property
	def isConsistent(self) -> bool:
		return self.root.role.signed.consistent_snapshot

	def save(self, repoRoot: Path) -> None:
		self.__class__.STRATEGY.save(repoRoot, False, self.root)

	@classmethod
	def load(cls, data: typing.Union[Path, bytes, str, dict], keys: typing.Optional[typing.Union[dict, KeyManager]] = None) -> "RepoSeed":
		if keys is None:
			keys = {}

		return cls(cls.STRATEGY.loadRoot(data), keys)

	def sign(self) -> None:
		self.keys.sign(self.root)


RepoSeed.__doc__ += FS_DETACHED_NOTICE


class RepoBuilder(Storeable):  # pylint:disable=too-few-public-methods
	"""
	A class to build a repo.
	Is initialized with a seed. Once initialized, a completely new repo can be built.
	If one wants to update an existing repo, he must load it.
	"""

	def __init__(self, seed: RepoSeed, keys: KeyManager, repoRoot: typing.Optional[Path] = None) -> None:
		self.seed = seed

		if isinstance(keys, dict):
			keys = KeyManager(keys)

		self.keys = keys
		self.ourRoles = {}  # type: dict[str, OurRole]
		self.userFiles = {}  # type: dict[str, bytes]
		self.load(repoRoot)

	def load(self, repoRoot: typing.Optional[Path]) -> None:
		self.ourRoles.update(self.seed.__class__.STRATEGY.loadOrCreateRoles(repoRoot, self.seed.isConsistent))

	@property
	def targets(self) -> OurRole:
		return self.ourRoles["targets"]

	@property
	def snapshot(self) -> OurRole:
		return self.ourRoles["snapshot"]

	@property
	def timestamp(self) -> OurRole:
		return self.ourRoles["timestamp"]

	def getUserFileNames(self) -> typing.Iterator[str]:
		for fn in self.userFiles:
			yield self.getPrefixForUserFile(fn) + fn

	def getPrefixForUserFile(self, fn: str) -> str:
		if self.seed.root.role.signed.consistent_snapshot:
			return self.targets.role.signed.targets[fn].hashes["sha256"] + "."

		return ""

	EXCLUDED_FROM_SNAPSHOT = (Snapshot, Timestamp)

	def bindContent(self) -> None:
		for localTargetPath, data in self.userFiles.items():
			t = TargetFile.from_data(localTargetPath, data)
			self.targets.role.signed.targets[str(localTargetPath)] = t
		self.targets.needsSigning = True
		self.keys.sign(self.targets)

	def bindMetadata(self) -> None:
		for oR in self.ourRoles.values():
			if not isinstance(oR.role.signed, self.__class__.EXCLUDED_FROM_SNAPSHOT):
				fileName = self.seed.__class__.STRATEGY.fileNameForRole(oR.fac, oR.version, self.seed.isConsistent)
				self.snapshot.role.signed.meta[fileName] = MetaFile(version=oR.role.signed.version)
		self.snapshot.needsSigning = True
		self.keys.sign(self.snapshot)

	def makeSnapshot(self) -> None:
		self.bindContent()
		self.bindMetadata()
		self.stamp()

	def stamp(self) -> None:
		self.timestamp.role.signed.snapshot_meta.version = self.snapshot.role.signed.version
		self.timestamp.needsSigning = True
		self.keys.sign(self.timestamp)

	def saveMeta(self, repoRoot: Path) -> None:
		for oR in self.ourRoles.values():
			self.seed.__class__.STRATEGY.save(repoRoot, self.seed.isConsistent, oR)

	def saveFiles(self, repoRoot: Path) -> None:
		for localTargetPath, data in zip(self.getUserFileNames(), self.userFiles.values()):
			p = repoRoot / localTargetPath
			p.write_bytes(data)

	def save(self, repoRoot: Path) -> None:
		self.saveMeta(repoRoot)
		self.saveFiles(repoRoot)


RepoBuilder.__doc__ += FS_DETACHED_NOTICE
