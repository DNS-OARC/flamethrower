# $FreeBSD$

PORTNAME=	flamethrower
PORTVERSION=	0.9
CATEGORIES=	dns net benchmarks ipv6

MAINTAINER=	pcarboni@gmail.com
COMMENT=	Stress testing for Domain Name System (DNS) servers

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE

BUILD_DEPENDS+=	ldns>=1.7:dns/ldns
BUILD_DEPENDS+=	libuv>=1.23:devel/libuv
LIB_DEPENDS+=	libldns.so:dns/ldns
LIB_DEPENDS+=	libuv.so:devel/libuv

USES=		cmake:insource,noninja compiler:c++17-lang pkgconfig

CONFIGURE_WRKSRC=	${WRKSRC}/build
BUILD_WRKSRC=	${WRKSRC}/build
INSTALL_WRKSRC=	${WRKSRC}/build

# ToDo:
#
# - Update the hash commit number once the man page
#   is integrated to the original source.
# - Update this Makefile to reflect the new
#   directory path for flame.1 file
#   and remove the files/flame.1 reference.
#

USE_GITHUB=	yes
GH_ACCOUNT=	DNS-OARC
GH_TAGNAME=	73b9815

PLIST_FILES=	bin/flame man/man1/flame.1.gz

PORTDOCS=	README.md

OPTIONS_DEFINE=	DOCS

do-install:
	${INSTALL_PROGRAM} ${BUILD_WRKSRC}/flame ${STAGEDIR}${PREFIX}/bin
	${INSTALL_MAN} ${FILESDIR}/flame.1 \
			 ${STAGEDIR}${MAN1PREFIX}/man/man1

post-install-DOCS-on:
	${MKDIR} ${STAGEDIR}${DOCSDIR}
	cd ${WRKSRC} && ${INSTALL_DATA} ${PORTDOCS} ${STAGEDIR}${DOCSDIR}

.include <bsd.port.mk>
