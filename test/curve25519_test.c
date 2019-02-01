#include <stdbool.h>
#include <string.h>
#include "curve25519.h"
#include "utils.h"
#include "rand.h"

#include "os_rand.h"

typedef struct
{
    const char *seed_hex;
    const char *public_hex;
    const char *private_hex;
} curve25519_dh_test_vector;

static curve25519_dh_test_vector test_vectors[] =
{
    {
        "a1376235f525789373981cc53196aca9",                                 /* seed */
        "ae08fcb27a0a655c483f8116cc8df14e412f96944d14cdf34f6fda3208fa6712", /* public-key */
        "92c520350c84ea52d45e1156eac0ad1719db04d6fbe5b025ab9a6e38daaca90b"  /* private-key */
    },
    {
        "d80b8c03a85c91a79e7624987e0911a7",                                 /* seed */
        "e25e376a5c4a8c75753aa0832ca96dabb1579828ddfbaad1df9f68e5a0616e28", /* public-key */
        "1935c23024682713900ffc101020e1d84fe9753db4afea9d14e5713efc4fcde0"  /* private-key */
    },
    {
        "05f15e1846d3751b5425a3076d33b1fa",                                 /* seed */
        "cfc76bf6fb1480977eec151b8fb637fb94bfa06424e2dee6d228c76a7b17095b", /* public-key */
        "5de3bc07b06c94787bc58165d0ac345ea954c7666d053f9f6855f4f8802f653c", /* private-key */
    },
    {
        "c068f3b96b7673e37178aef8a8988835",                                 /* seed */
        "92bc13a938c15dba73648902227562767665bf84b8ff3f44b36ea38340f9ee33", /* public-key */
        "c5301379624ca80b3c4113506de5ce35cbc880051b337751e00daf42ad75addb", /* private-key */
    },
    {
        "417a97b5ca7f14fcfb0c5aaa0f83990b",                                 /* seed */
        "12c1713cb6a832a8e966c9102fa194d103edefe3371edfad674718673a823d49", /* public-key */
        "ed0719665f574c7cc933176df3dd9278dbeea92df2c21ea169fa72e9a32eaf36", /* private-key */
    },
    {
        "e8b3a4e13ccc2cd949a748a6bc748f11",                                 /* seed */
        "715e1b43a83fe92ff61ad007a1d0901eba90b3c5fcfb4a1270284edab14afd59", /* public-key */
        "5be321252ff55306ec2ceaf200504abd956b12b82e2548987ed3735d2075b147", /* private-key */
    },
    {
        "9c425ec1769114f0e8195192723a8340",                                 /* seed */
        "61bc8cf3e7fcb1f663b38a218a9a5001c65d9be56db364977e2a5cc52d1cf74e", /* public-key */
        "e17f544e25afedd508bbff7039ceaca1215bf4927577f3e242389da8c6b2030d", /* private-key */
    },
    {
        "1b9c34786239593354ae0a32a72ffc70",                                 /* seed */
        "1d5a8819cb225f25ae2de148c2e71f774192183368fed48a5816ba223d0c9467", /* public-key */
        "9a41a08537a8d8f18303bb0442b4416c373134767dd3816e7f3233c0e06e8418", /* private-key */
    },
    {
        "ecf9bfde31e1d118c3aca9173c47f3c2",                                 /* seed */
        "85a961d9f57dcbb758b2c8b45979add3f92b3f867184ab914368baab5c69fe26", /* public-key */
        "d84aa36741316e6fdcd123d67312a4ab5f6f8cff6e2085f34305d4552f5995d4", /* private-key */
    },
    {
        "86285c1a76839e62de813ec65d9dca90",                                 /* seed */
        "f6e99332e3b5021ecbbe41333918cdccdb4fdb71c95a07fa5faa6d9d6dfc6e6f", /* public-key */
        "fc73b16a76301e096b625713abd55596eb01796e68195bf67f76d68e2798b830", /* private-key */
    },
    {
        "f212edbee20d94a48a08dd440bc60d16",                                 /* seed */
        "3720b6a54ec0755c6c19a730b2843bf8dc6c9cd97f7f0c18757339a922c27b5c", /* public-key */
        "b4d38c76a7e60678bf4fb71d7f49754a2ff5b349d1db1fc49f79b208c9f99e04", /* private-key */
    },
    {
        "f44f1813b7e7d889e1f87ee70b66518e",                                 /* seed */
        "4a669f1c6227cf8c0b759e3fe7aa884a9a21c977f6b56288a0245ea286deec69", /* public-key */
        "a3ef5295ffcb7b75b6151e30291a4817dff0580a6a8e827ba20b0e595b4dac73", /* private-key */
    },
    {
        "79f420cb49b36b3d2696a87f1374a6bc",                                 /* seed */
        "dc897f80d84feaabf2ec24173be992330bbf7204ca21e8dc4dcf15c362e43a73", /* public-key */
        "6a207317e483a3eb5893f97c098dcca4cdd03d6931ab0173ad4826d5350811cc", /* private-key */
    },
    {
        "32938e4f798d5666d6659c74a05d1a49",                                 /* seed */
        "c5174a610f5b3ad1f374dfffaadea535128f5898a9643e8dd1de7ae08bf0de0f", /* public-key */
        "e3040a63330ad8762eb895e33bcb5d0876040cce0febb8d5547647cd3fd0d93a", /* private-key */
    },
    {
        "174267446f727dff5a958118de7a95dd",                                 /* seed */
        "5c928b1472dd5dd6e00f412678b4d83d838d0d414e2f003e504884e5fe5bcc6d", /* public-key */
        "1c8b94b1965e5660bd384fb657f9e43aea3d4b4666826b9f45c467aef8d5b293", /* private-key */
    },
    {
        "230e3fb9097d18abff77c8da536e59a1",                                 /* seed */
        "579f36593bc9a3936e96ec9bce206aae49654feff83dda05c7fc441fddf1e246", /* public-key */
        "2546bdae2612c8824e401e722d108f6fe8355457cee74cc0076076e17112a4e2", /* private-key */
    },
    {
        "663b958785de20ad187d48d9fefd2cf6",                                 /* seed */
        "caf8e27a0b2cc017bcca9d04fcd2b9bd928a7330a45409c1c01ea72815c3a330", /* public-key */
        "0129d08e89274b96bcab11694fad38c0eeb05c2ba832bba52de1adaeeeffcac6", /* private-key */
    },
    {
        "035143ec31b678703168cd1a6abbb400",                                 /* seed */
        "a4026c797764e99e8af1752842df1b29fc5cfdc4cc726b7ea5bd457af196b06e", /* public-key */
        "49efb56e8cbbd0f9ec0d5a2dd9c570db66f8fd4a26426698880ada8f6419b8bc", /* private-key */
    },
    {
        "d97a8255460909b28913104894dbcc6a",                                 /* seed */
        "b09ae4be154e3e7103c18ceace3e192daac75b9362845eb2a433710af9209918", /* public-key */
        "e092ea08f31f56e7704d180a3efbd5b54410aecc4292e8fe862fd327f04d25ac", /* private-key */
    },
    {
        "bc39b432452673dce85116bb5b569782",                                 /* seed */
        "e8f14230e06ff71e182352fcf6226f782f17a8f26a985c3773a588c284115f22", /* public-key */
        "b49cba8cf4edc3c36f998893f437dbec44ac7b53bbe0e34dea26270e2d9c699b", /* private-key */
    },
    {
        "eeababc1a9bc82b323ae04838e70672c",                                 /* seed */
        "7e21c8a1ca776eb3437548a5e6c7434773bfe4812a674f019e0688fd89319963", /* public-key */
        "989cb5e7cea7cf9546a8a468cde496ced39ce7afbb2974f2fff23a99bd0e997b"  /* private-key */
    },
    {
        "044d1346df32e8535ea5024a91717c37",                                 /* seed */
        "271d4e108ea2c85a27d596e38bc3ce349456329fbb57e93d99e16aeda1db2f7c", /* public-key */
        "91404d89278648e3cb4755d1186054fd517303a323163f29abe79c05ef40bc07"  /* private-key */
    },
    {
        "6266a0e196ffeeeebbf3750f10957a36",                                 /* seed */
        "bc49acf3b2137f3603d6d26c472061d986d2876b97e04e9a9b2b935b2ae25131", /* public-key */
        "eb9721f470e2d0d5a7b6d7f8286844b1edf6abafddbae864d38dc9c2fb17005e"  /* private-key */
    },
    {
        "750c9170939db7040fda9580e9790206",                                 /* seed */
        "050351fa750ef05ef9be063651d1d91d8f3fc6c3d0a380b867050340fd1f3f4d", /* public-key */
        "a7c320fcfa702cbb9c3c796f79344a657491f3fcf3009fe097cbf3ec4834a85b"  /* private-key */
    },
    {
        "e3f6b2db8a67af105169e8965b3d8dfb",                                 /* seed */
        "304013f9ab4b53317412bbb2d75056dd0eec52e26d43267a26f5e87b6cd03f23", /* public-key */
        "456dd08d3da35c73ffd4223cfa71e23b365308a1bb762ad49ef5d8397bea968f"  /* private-key */
    },
    {
        "b69fc433a2836e85a5f78a28d1ea5478",                                 /* seed */
        "9cc8e7f40b6a88cb2ff8383b9461a2167fa305fba4cb54c9ca5ae38ebf515a6e", /* public-key */
        "004cbddcc8d45d355988b6ddc1d3b0e1fd3591ada3e0c0f2878b82994e1e793c"  /* private-key */
    },
    {
        "422ce8903bd8924561ea251a958da914",                                 /* seed */
        "48a1c97710200626961f767ade6c402e2bb492a2d399d0215920235a0857e541", /* public-key */
        "9c3ad75954716eb9b485f72539052d9e11b536e9b6a72ac3b2f6b5c99b2f616d"  /* private-key */
    },
    {
        "e133406f531855aabe117101d39dd29a",                                 /* seed */
        "41308801e15e093e77e5e1d1b9da62fa4ce249bec8211f198766d18de6618a7e", /* public-key */
        "f831247bdd4d396338fd5e0463e7c5e472e1af149af79393c7cd472722a68e3e"  /* private-key */
    },
    {
        "7ff8a3e691e14c5125962f97dc069e99",                                 /* seed */
        "4b1d09b18d510c874dd09816f64375a12c9e2e8260061592e0f23e73b075f532", /* public-key */
        "02a40807b05954d1c60aa9f08badcd5fa3a02c2efa92c0c0eed68212747c9e2f"  /* private-key */
    },
    {
        "0a67e6c767f8bb0ee48e25dfd104eada",                                 /* seed */
        "f5bc7c80d40be84c77f400df704da899ce2fac4c15f2fa1a6e667ddda539f23e", /* public-key */
        "b55c31bf31aba0bc8c52c94676b2ad08b4a03e3ed5f6a832870bfb2a67a447fb"  /* private-key */
    },
    {
        "a983c1d193c06aa891e9fff803ce499b",                                 /* seed */
        "b43d0268478698ad73e7a3c8ee091c3d8e18067f2f001c1084a6a4097bc0cf79", /* public-key */
        "ddd71684a0d5a879e78c6251687cfaa481adb04e16df64bdeeb14d96c28897ad"  /* private-key */
    },
    {
        "c7f63a125634082caf07eb5b526cac03",                                 /* seed */
        "786ab02e48d7d693448ec50e736297bc41cf038cd125107ca3ae3c23af663140", /* public-key */
        "4bc7c417861bae3e2eda4161a49a4068a647e4007e7fd2123be5d60dd6e19442"  /* private-key */
    },
    {
        "712c29a3786954155e221dc8a97c12e5",                                 /* seed */
        "eddfbc0a12f0a3f469aec9175ca7346f2b300447b3c365679ca185d980435a5c", /* public-key */
        "74330ccfef361ee92c06b46ef54a8c1b6b98fbe50cbcfa7d402e26d2e840c21b"  /* private-key */
    },
    {
        "ecbba35c6bd20b1ce94a9b0a3655d8b6",                                 /* seed */
        "d01fbcb602cffbf14057db92834efb2acd1e865f747b92a987bc7433a71bcf4f", /* public-key */
        "002b695bf6747b672964d81cfe703f9f9ab6aedfb87e77b0fceed2d0475a36af"  /* private-key */
    },
    {
        "a9247d235eeaf3d916291364e2a45c33",                                 /* seed */
        "a03ed30947ea3b34b95041d87d745cbf75e530360b6f6ebc2d68cfa47dbad757", /* public-key */
        "515b4d5e4adb03c9683c8f8aa108a1e0021f191007368ab41e3ded2404b3c42f"  /* private-key */
    },
    {
        "40d975eb1c69b276b65233ae2ace1371",                                 /* seed */
        "169481a35b745d58f2f68219010839c6ab20e1dd3c2d35b8eaa80beb3ee9a223", /* public-key */
        "c3067f8ce6b5257fe8da0aed93d9ede81327391e1ca8139bf8a58cd411366f88"  /* private-key */
    },
    {
        "c284d762d09cce32679501029524919b",                                 /* seed */
        "4ac805341fa68effb4f53095fbe2426839ed8706fcfc64e6771633d15649176a", /* public-key */
        "3b205fb9dc4949865e61a78f6466a09f4f7d31772c2e0707eb5092811c0a2f2d"  /* private-key */
    },
    {
        "b945f24b41cc8a9134d49db3efe7a116",                                 /* seed */
        "9bfcb1d193345e31c632537fbe29fc52fba465ef21a85b286213f0e8fce0d45b", /* public-key */
        "03abac55b9c83c6b0ea178c9ee9448a656eb6c3d4412df90966cc0cf980c9d69"  /* private-key */
    },
    {
        "e7c5de2239ce3fa29f606bd170f3ad11",                                 /* seed */
        "acc4763de1962bd927e063a80b4043c2b6df2a457f9c9e3e49fddb2d67fe8e7f", /* public-key */
        "7446a285f9a68e2e1da534d0ea76ff553ec7a09116ee63cdf593b0e75552dbf1"  /* private-key */
    },
    {
        "c3eeaf97731ced7bbbfa1ef266ec6325",                                 /* seed */
        "d6d2fa7034a938f5dcc169ec7aebe1d5ef2f5a43eadb0e69e4f59b55e8b74378", /* public-key */
        "00f3daa7fa63a8a9f26fc95fd6cd6817c6cea3f97609ea1e538da3fdd6c2a199"  /* private-key */
    },
    {
        "e58491d26748eaaa1d8f23ea1097944f",                                 /* seed */
        "fde1b95163db7673653ac35b67ad3f046b3c24f109a8f026d1ab86f2d4f4dc2c", /* public-key */
        "07341977b049d043c5ec85a56171e66684ad42b16355088d52b63353152cb4a4"  /* private-key */
    },
    {
        "6312b068dee83b5a64693ea0df1141c4",                                 /* seed */
        "b561fcf26ebbf5eb0714907e2a1c306df9a6481c58f21f2cc30e73bba66dcc61", /* public-key */
        "7304e551a20ab4ca029f8860485f71b3312ff19a70144254f764654ec2288e43"  /* private-key */
    },
    {
        "5596345f86e014faa1687be78ca3a661",                                 /* seed */
        "ee4b9fab9ad118d906731a50368b487cf166da83e91153098626a9d2a5505412", /* public-key */
        "6314a4bc48934ca9137a1e36b75f441e8823e937753dfe7c7921f5fc5847c4f1"  /* private-key */
    },
    {
        "17c06b4b1f62dcb512a6d3e5816c2446",                                 /* seed */
        "70bc344480a17ace513675a2d313ab7460fb21dfacf6f883d8642e5d13a71279", /* public-key */
        "33db51120bfc4c2dfff870b3853fbaade237952935b777ae9b772084adcdf4f5"  /* private-key */
    },
    {
        "dc4036699a76b113f946d630178131df",                                 /* seed */
        "1ebbfb68c105be220182c49ac42add72233350efaf76ec465a26d874a933cf42", /* public-key */
        "a7370164779d766e9903372a42b2226080e87810dd3b7deee45b5b8cc4578c22"  /* private-key */
    },
    {
        "2200f9120e635a1f1024a20e35d7cfcf",                                 /* seed */
        "74624688884b1eae36140a99e451b8ee51d4e6893f0fc6d59ae129945a9f5217", /* public-key */
        "9d058a65de22d968dfa67b46cab4337c71ee3fd0db4a40e1c3d8c2179ecdd02b"  /* private-key */
    },
    {
        "cbce65b5b0e20884703cab14203ee9e4",                                 /* seed */
        "f4eb7cedc65fb55178593a3cc66aff25c5c1a22583e0e05ce399653e4416c850", /* public-key */
        "be91a4a960859ece6de30994706d6ff2b126748874643c1591d3840b7e586143"  /* private-key */
    },
    {
        "97664c437921319a3093ed35baa59e05",                                 /* seed */
        "1c4fc4f9130240ed032891985232ed9f0630e5ab8a36d1834ab406b2bbe0ac5e", /* public-key */
        "915d4939db35ef600fc238a825b7a77eed763e5efb9117351675236e164cf7bc"  /* private-key */
    },
    {
        "3e6e400613dfc336be2911a18f1932c4",                                 /* seed */
        "afeb075fe1126c93e7eb2d75c156516df9048099d7d76735de4906945aa8ab40", /* public-key */
        "fb59e67ac9881caac41766bab09d0515beae9ddbb7dc7025fefacb32538c7f9c"  /* private-key */
    },
    {
        "d40f5474f646774292a6fe4dd96c8194",                                 /* seed */
        "8d29737462de02b81417ebe304ed804ccb3635d636922c4e32c111a01200257d", /* public-key */
        "1089cfb24669173a33d3cb072ca73c8cce922e5496fc0b9c8358c02c79e9961a"  /* private-key */
    }
};

bool curve25519_random_keypair_test()
{
    int32_t idx;
    bool result = true;
    uint8_t public_key[CURVE25519_PUBLIC_KEY_SIZE];
    uint8_t private_key[CURVE25519_PRIVATE_KEY_SIZE];
    uint8_t seed[16];
    uint8_t pk[CURVE25519_PUBLIC_KEY_SIZE];
    uint8_t sk[CURVE25519_PRIVATE_KEY_SIZE];
    curve25519_dh_test_vector *ptr = NULL;

    for (idx = 0;
         result && idx < (int)(sizeof(test_vectors)/sizeof(curve25519_dh_test_vector));
         idx++)
    {
        result = false;
        ptr = &test_vectors[idx];
        hex_string_to_byte_array(seed, ptr->seed_hex);
        hex_string_to_byte_array(pk, ptr->public_hex);
        hex_string_to_byte_array(sk, ptr->private_hex);

        bdap_randominit(seed, sizeof(seed));
        
        crypto_memzero(private_key, sizeof(private_key));
        crypto_memzero(public_key, sizeof(public_key));
        
        result = curve25519_random_keypair(public_key, private_key) &&
                (memcmp(public_key, pk, CURVE25519_PUBLIC_KEY_SIZE) == 0) &&
                (memcmp(private_key, sk, CURVE25519_PRIVATE_KEY_SIZE) == 0);
    }

    return result;
}
