import typing
from pathlib import Path
from shutil import rmtree

from .Repo import Repo


class RepoManager:
	__slots__ = ("root", "petNames")

	REPO_CLASS = Repo

	def __init__(self, reposRoot: Path) -> None:
		self.root = reposRoot
		self.petNames = None
		self.refresh()

	def refresh(self) -> None:
		self.petNames = []
		if self.root.exists():
			for el in self.root.iterdir():
				if el.is_dir():
					self.petNames.append(el.name)

	def __getitem__(self, petName: str) -> Repo:
		return self.repoByPetName(petName)

	def __delitem__(self, petName: str):
		rmtree(self.getRepoDirByPetname(petName))

	def __iter__(self):
		return iter(self.petNames)

	def __len__(self):
		return len(self.petNames)

	def getRepoDirByPetname(self, petName: str) -> Path:
		return self.root / petName

	def repoByPetName(self, petName: str, localMetadata: typing.Optional[dict] = None) -> Repo:
		return self.__class__.REPO_CLASS(self.getRepoDirByPetname(petName), localMetadata)

	def add(self, petName: str, seed: dict, baseURIs: typing.Optional[typing.Iterable[str]] = None) -> typing.Dict[str, typing.List[str]]:
		return self.__class__.REPO_CLASS.setup(self.root, seed, petName, baseURIs)
