CREATE TABLE "texturepacks" (
	"ID" INTEGER NOT NULL,
	"name" TEXT NOT NULL,
	"description" TEXT NOT NULL DEFAULT 'N/A',
	"creator" TEXT NOT NULL DEFAULT 'N/A',
	"logo" TEXT NOT NULL DEFAULT 'https://robtopgames.com/Images/icon_200.png',
	"download" TEXT NOT NULL,
	"version" TEXT NOT NULL DEFAULT '1.0.0',
	"gameVersion" TEXT NOT NULL DEFAULT '2.206',
	"feature" INTEGER NOT NULL DEFAULT 0,
	"downloads" INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY("ID" AUTOINCREMENT)
);