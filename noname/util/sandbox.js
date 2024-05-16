const FILE_URL = import.meta.url;

const SandboxExposer = Symbol("Sandbox.Exposer");
const SandboxExposer2 = Symbol("Sandbox.Exposer2");

const SandboxSignal_InitDomain = Symbol("InitDomain");
const SandboxSignal_GetMarshalledProxy = Symbol("GetMarshalledProxy");
const SandboxSignal_SetMarshalledProxy = Symbol("SetMarshalledProxy");
const SandboxSignal_GetWindow = Symbol("GetWindow");
const SandboxSignal_EnterDomain = Symbol("EnterDomain");
const SandboxSignal_ExitDomain = Symbol("ExitDomain");
const SandboxSignal_UnpackProxy = Symbol("UnpackProxy");
const SandboxSignal_Marshal = Symbol("Marshal");
const SandboxSignal_TrapDomain = Symbol("TrapDomain");
const SandboxSignal_NotifyDomain = Symbol("NotifyDomain");

function isPrimitive(obj) {
    return Object(obj) !== obj;
}

/**
 * ```plain
 * AccessAction枚举
 * 提供给Rule类作为权限ID
 * 对应 Proxy 的12种拦截器
 * ```
 */
class AccessAction {
    // static CALL     = 0;  // apply
    // static NEW      = 1;  // construct
    // static READ     = 2;  // get
    // static WRITE    = 3;  // set
    // static DESCRIBE = 4;  // getOwnPropertyDescriptor
    // static DEFINE   = 5;  // defineProperty
    // static TRACE    = 6;  // getPrototypeOf
    // static META     = 7;  // setPrototypeOf
    // static SEAL     = 8;  // preventExtensions
    // static EXISTS   = 9;  // has
    // static LIST     = 10; // ownKeys
    // static DELETE   = 11; // delete

    /** ```Reflect.apply``` */
    static CALL = 0;
    /** ```Reflect.construct``` */
    static NEW = 1;
    /** ```Reflect.get``` */
    static READ = 2;
    /** ```Reflect.set ``` */
    static WRITE = 3;
    /** ```Reflect.getOwnPropertyDescriptor``` */
    static DESCRIBE = 4;
    /** ```Reflect.defineProperty``` */
    static DEFINE = 5;
    /** ```Reflect.getPrototypeOf``` */
    static TRACE = 6;
    /** ```Reflect.setPrototypeOf``` */
    static META = 7;
    /** ```Reflect.preventExtensions``` */
    static SEAL = 8;
    /** ```Reflect.has``` */
    static EXISTS = 9;
    /** ```Reflect.ownKeys``` */
    static LIST = 10;
    /** ```Reflect.delete``` */
    static DELETE = 11

    /**
     * 判断给定的action是否是AccessAction
     * 
     * @param {number} action 
     * @returns 
     */
    static isAccessAction(action) {
        return typeof action == "number"
            && action >= 0 && action < 12;
    }
}

/**
 * ```plain
 * 指定一个对象的封送规则
 * 
 * 是否允许对象进行封送
 * 是否允许对象封送到某个具体的运行域
 * 是否允许封送的对象进行特定的操作
 * ```
 */
class Rule {
    #allowMarshal = true;

    /** @type {WeakSet<Domain>?} */
    #allowMarshalTo = null;
    /** @type {WeakSet<Domain>?} */
    #disallowMarshalTo = null;

    #permissions = new Array(12).fill(false);
    #accessControl = null;

    /**
     * @param {Rule} rule 
     */
    constructor(rule = null) {
        if (rule instanceof Rule) {
            this.#allowMarshal = rule.#allowMarshal;
            this.#allowMarshalTo = rule.#allowMarshalTo;
            this.#disallowMarshalTo = rule.#disallowMarshalTo;
            this.#permissions = rule.#permissions.slice();
            this.#accessControl = rule.#accessControl;
        }
    }

    /**
     * ```plain
     * 是否允许对象进行封送
     * ```
     * 
     * @type {boolean}
     */
    get canMarshal() {
        return this.#allowMarshal;
    }

    /**
     * ```plain
     * 是否允许对象进行封送
     * ```
     * 
     * @type {boolean}
     */
    set canMarshal(newValue) {
        this.#allowMarshal = !!newValue;
    }

    /**
     * ```plain
     * 检查当前的规则是否允许封送到指定的运行域
     * ```
     * 
     * @param {Domain} domain 
     * @returns {boolean} 
     */
    canMarshalTo(domain) {
        if (!this.#allowMarshal)
            return false;

        if (this.#allowMarshalTo)
            return this.#allowMarshalTo.has(domain);
        else if (this.#disallowMarshalTo)
            return !this.#disallowMarshalTo.has(domain);

        return true;
    }

    /**
     * ```plain
     * 将特定的运行域添加到当前对象的封送白名单
     * 
     * 请注意，封送白名单与黑名单不能同时指定
     * ```
     * 
     * @param {Domain} domain 
     */
    allowMarshalTo(domain) {
        if (!this.#allowMarshalTo) {
            if (this.#disallowMarshalTo)
                throw new TypeError("封送黑名单与封送白名单不能同时存在");

            this.#allowMarshalTo = new WeakSet();
        }

        this.#allowMarshalTo.add(domain);
    }

    /**
     * ```plain
     * 将特定的运行域添加到当前对象的封送黑名单
     * 
     * 请注意，封送白名单与黑名单不能同时指定
     * ```
     * 
     * @param {Domain} domain 
     */
    disallowMarshalTo(domain) {
        if (!this.#disallowMarshalTo) {
            if (this.#allowMarshalTo)
                throw new TypeError("封送黑名单与封送白名单不能同时存在");

            this.#disallowMarshalTo = new WeakSet();
        }

        this.#disallowMarshalTo.add(domain);
    }

    /**
     * ```plain
     * 检查给定的AccessAction是否被允许
     * ```
     * 
     * @param {number} action 
     * @returns {boolean} 
     */
    isGranted(action) {
        if (!AccessAction.isAccessAction(action))
            throw new TypeError("参数 action 不是一个有效的操作");

        return this.#permissions[action];
    }

    /**
     * ```plain
     * 指定给定的AccessAction是否被允许
     * ```
     * 
     * @param {number} action 
     * @param {boolean} granted 
     */
    setGranted(action, granted) {
        if (!AccessAction.isAccessAction(action))
            throw new TypeError("参数 action 不是一个有效的操作");

        this.#permissions[action] = !!granted;
    }

    /**
     * ```plain
     * 判断在给定的AccessAction与指定的参数下是否允许访问
     * ```
     * 
     * @param {number} action 
     * @param  {...any} args 
     * @returns {boolean} 
     */
    canAccess(action, ...args) {
        if (!this.isGranted(action))
            return false;
        if (this.#accessControl
            && !this.#accessControl(action, ...args))
            return false;

        return true;
    }

    /**
     * ```plain
     * 设置当前的权限控制器
     * ```
     * 
     * @param {(...) => boolean} accessControl 
     */
    setAccessControl(accessControl) {
        if (typeof accessControl != "function")
            throw new TypeError("无效的权限控制器");
        if (this.#accessControl)
            throw new TypeError("权限控制器已经被设置");

        this.#accessControl = accessControl;
    }
}

/**
 * ```plain
 * 全局变量映射表
 * 
 * 在下表中标记的全局变量，
 * 封送时将不使用代理封送，
 * 而是直接映射成另一个运行域对应的全部变量
 * 
 * 映射表项格式:
 * string: 全局变量路径
 * 例如: /Object/assign 指向 window.Object.assign
 * 同时路径也是映射的键名
 * array: [全局变量名称, 对应的获取代码]
 * 例如: [/AsyncFunction, (async()=>{}).constructor]
 * 指向异步函数的构造函数，使用/AsyncFunction作为映射键名
 * 
 * 请注意，映射键名不得相同，不然会导致相互覆盖
 * ```
 */
const GLOBAL_PATHES = Object.freeze([
    "/Object",
    "/Array",
    "/Function",
    "/Promise",
    "/Math",
    "/Date",
    "/String",
    "/Number",
    "/Boolean",
    "/BigInt",
    "/Reflect",
    "/RegExp",
    "/Proxy",
    "/Symbol",
    "/Error",
    "/TypeError",
    "/SyntaxError",
    "/RangeError",
    "/EvalError",
    "/EvalError",
    "/ReferenceError",
    "/JSON",
    "/Map",
    "/Set",
    "/WeakRef",
    "/WeakMap",
    "/WeakSet",
    ["/Generator", "(function*(){})().constructor"],
    ["/GeneratorFunction", "(function*(){}).constructor"],
    ["/AsyncFunction", "(async()=>{}).constructor"],
    ["/AsyncGenerator", "(async function*(){})().constructor"],
    ["/AsyncGeneratorFunction", "(async function*(){}).constructor"],
    "/setTimeout",
    "/setInterval",
    "/setImmediate",
    "/clearTimeout",
    "/clearInterval",
    "/clearImmediate",
    "/eval",
    "/alert",
    "/confirm",
    "/console",
]);

/**
 * ```plain
 * 为每个运行域的全局对象提供封送映射
 * 
 * 非暴露类
 * ```
 */
class Globals {
    /** @type {WeakMap<Domain, [WeakMap, Object]>} */
    static #globals = new WeakMap();

    static parseFrom(path, window) {
        if (typeof path == "string") {
            const items = path.split("/").filter(Boolean);
            let obj = window;

            for (const item of items)
                obj = obj[item];

            return [path, obj];
        } else
            return [path[0], window.eval(path[1])];
    }

    /**
     * @param {Domain} domain 
     */
    static ensureDomainGlobals(domain) {
        if (!this.#globals.has(domain)) {
            const window = domain[SandboxExposer](SandboxSignal_GetWindow);
            const globals = [new WeakMap(), {}];

            for (const path of GLOBAL_PATHES) {
                const [key, obj] = this.parseFrom(path, window);

                if (obj == null)
                    continue;

                globals[0].set(obj, key);
                globals[1][key] = obj;
            }

            this.#globals.set(domain, globals);
        }
    }

    /**
     * @param {Domain} domain 
     * @param {Object} obj 
     */
    static findGlobalKey(domain, obj) {
        this.ensureDomainGlobals(domain);
        const globals = this.#globals.get(domain);
        return globals[0].get(obj);
    }

    /**
     * @param {Domain} domain 
     * @param {string} key 
     */
    static findGlobalObject(domain, key) {
        this.ensureDomainGlobals(domain);
        const globals = this.#globals.get(domain);
        return globals[1][key];
    }

    /**
     * @param {Object} obj 
     * @param {Domain} sourceDomain 
     * @param {Domain} targetDomain 
     */
    static mapTo(obj, sourceDomain, targetDomain) {
        const key = this.findGlobalKey(sourceDomain, obj);

        if (!key)
            return undefined;

        return this.findGlobalObject(targetDomain, key);
    }
}

/**
 * ```plain
 * 提供运行域之间的对象封送
 * ```
 */
class Marshal {
    static #revertTarget = Symbol("Marshal.revertTarget");
    static #sourceDomain = Symbol("Marshal.sourceDomain");

    static #marshalRules = new WeakMap();
    static #marshalledProxies = new WeakSet();

    constructor() {
        throw new TypeError("Marshal 类无法被构造");
    }

    static #shouldMarshal(obj) {
        if (obj === Marshal
            || obj === Rule
            || obj === AccessAction
            || obj === Domain
            || obj === Sandbox
            || obj instanceof Rule
            || obj instanceof Domain)
            return false;

        return true;
    }

    static #strictMarshal(obj) {
        return obj instanceof Sandbox;
    }

    /**
     * ```plain
     * 拆除封送代理
     * ```
     * 
     * @typedef {[ 
     *     Domain,
     *     Object,
     * ]} Reverted
     * @param {any} proxy 
     * @returns {Reverted}
     */
    static #revertProxy(proxy) {
        return [
            proxy[this.#sourceDomain],
            proxy[this.#revertTarget],
        ];
    }

    /**
     * ```plain
     * 检查封送缓存
     * ```
     * 
     * @param {Object} obj 
     * @param {Domain} domain 
     * @returns {Object?} 
     */
    static #cacheProxy(obj, domain) {
        return domain[SandboxExposer]
            (SandboxSignal_GetMarshalledProxy, obj);
    }

    /**
     * ```plain
     * 获取指定对象的封送规则引用
     * ```
     * 
     * @param {Object} obj 
     * @returns {{rule: Rule}} 
     */
    static #ensureRuleRef(obj) {
        let rule = this.#marshalRules.get(obj);

        if (!rule)
            this.#marshalRules.set(obj, rule = { rule: null });

        return rule;
    }

    /**
     * ```plain
     * 判断某个对象是否指定了封送规则
     * ```
     * 
     * @param {Object} obj 
     * @returns {boolean} 
     */
    static hasRule(obj) {
        return this.#marshalRules.has(obj);
    }

    /**
     * ```plain
     * 指定某个对象的封送规则
     * ```
     * 
     * @param {Object} obj 
     * @param {Rule} rule 
     */
    static setRule(obj, rule) {
        if (this.#marshalledProxies.has(obj))
            throw new ReferenceError("无法为封送对象设置封送规则");

        const ref = this.#ensureRuleRef(obj);

        if (ref.rule)
            throw new ReferenceError("对象的封送规则已经被设置");

        ref.rule = rule;
    }

    /**
     * ```plain
     * 判断某个对象是否是其他运行域被封送的对象
     * ```
     * 
     * @param {Object} obj 
     * @returns {boolean} 
     */
    static isMarshalled(obj) {
        return this.#marshalledProxies.has(obj);
    }

    /**
     * ```plain
     * 陷入某个运行域并执行代码
     * ```
     * 
     * @param {Domain} domain 
     * @param {() => any} action 
     */
    static #trapDomain(domain, action) {
        const prevDomain = Domain.current;

        // 如果可能，应该尽量避免陷入相同运行域
        if (prevDomain === domain)
            return console.warn("trapDomain 处于相同 domain"), action();

        Domain[SandboxExposer2](SandboxSignal_EnterDomain, domain);

        try {
            return action();
        } catch (e) {
            throw Marshal.#marshal(e, prevDomain);
        } finally {
            Domain[SandboxExposer2](SandboxSignal_ExitDomain);
        }
    }

    /**
     * ```plain
     * 封送数组
     * ```
     * 
     * @param {Array} array 
     * @param {Domain} targetDomain 
     */
    static #marshalArray(array, targetDomain) {
        if (targetDomain.isFrom(array))
            return array;

        const window = targetDomain[SandboxExposer](SandboxSignal_GetWindow);
        const newArray = new window.Array(array.length);

        for (let i = 0; i < newArray.length; i++)
            newArray[i] = this.#marshal(array[i], targetDomain);

        return newArray;
    }

    /**
     * @param {Object} obj 
     * @param {Domain} targetDomain 
     * @returns {Object} 
     */
    static #marshal(obj, targetDomain) {
        // 基元封送
        if (isPrimitive(obj))
            return obj;

        // 尝试拆除代理
        let [sourceDomain, target] =
            this.#marshalledProxies.has(obj)
                ? this.#revertProxy(obj)
                : [Domain.current, obj];

        // target: 确保拆除了封送代理的对象
        // sourceDomain: target所属的运行域
        // targetDomain: 要封送到的运行域

        if (sourceDomain === targetDomain)
            return target;

        if (this.#strictMarshal(target))
            throw new TypeError("对象无法封送");
        if (!this.#shouldMarshal(target))
            return target;

        // 异步封送
        if (sourceDomain.isPromise(target)) {
            const marshaller = (value => {
                return Marshal.#trapDomain(sourceDomain, () => {
                    return Marshal.#marshal(value, targetDomain);
                });
            })
            target = target.then(marshaller,
                e => { throw marshaller(e); });
        } else {
            // 全局变量封送
            const mapped = Globals.mapTo(target, sourceDomain, targetDomain);

            if (mapped != null)
                return mapped;

            // 错误封送
            if (sourceDomain.isError(target)) {
                const errorCtor = target.constructor;
                const mappedCtor = Globals.mapTo(errorCtor, sourceDomain, targetDomain);

                if (mappedCtor) {
                    const newError = new mappedCtor();
                    Object.defineProperties(newError,
                        Object.getOwnPropertyDescriptors(target));
                    return newError;
                }
            }
        }

        // 检查封送权限
        const ruleRef = this.#ensureRuleRef(target);
        const rule = ruleRef.rule;

        if (rule && !rule.canMarshalTo(targetDomain))
            throw new TypeError("无法将对象封送到目标运行域");

        // 检查封送缓存
        const cached = this.#cacheProxy(target, targetDomain);

        if (cached)
            return cached;

        // 创建封送代理
        const proxy = new Proxy(target, {
            apply(target, thisArg, argArray) {
                const marshalledThis = Marshal.#marshal(thisArg, sourceDomain);
                const marshalledArgs = Marshal.#marshalArray(argArray, sourceDomain);

                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.CALL,
                        target, marshalledThis, marshalledArgs))
                        throw new ReferenceError("Access denied");

                    const result = Reflect.apply(target, marshalledThis, marshalledArgs);
                    return Marshal.#marshal(result, targetDomain);
                });
            },
            construct(target, argArray, newTarget) {
                const marshalledArgs = Marshal.#marshalArray(argArray, sourceDomain);
                const marshalledNewTarget = Marshal.#marshal(newTarget, sourceDomain);

                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.NEW,
                        target, argArray, newTarget))
                        throw new ReferenceError("Access denied");

                    const result = Reflect.construct(target, marshalledArgs, marshalledNewTarget);
                    return Marshal.#marshal(result, targetDomain);
                });
            },
            defineProperty(target, property, attributes) {
                let getter = attributes.get;
                let setter = attributes.set;

                if (typeof getter == "function")
                    getter = Marshal.#marshal(getter, sourceDomain);
                if (typeof setter == "function")
                    setter = Marshal.#marshal(setter, sourceDomain);

                const window = sourceDomain[SandboxExposer](SandboxSignal_GetWindow);
                const descriptor = new window.Object();

                if ("value" in attributes)
                    descriptor.value = Marshal.#marshal(attributes.value, sourceDomain);
                if ("get" in attributes)
                    descriptor.get = getter;
                if ("set" in attributes)
                    descriptor.set = setter;
                if ("writable" in attributes)
                    descriptor.writable = !!attributes.writable;
                if ("enumerable" in attributes)
                    descriptor.enumerable = !!attributes.enumerable;
                if ("configurable" in attributes)
                    descriptor.configurable = !!attributes.configurable;

                const isSourceDomain = sourceDomain === Domain.current;
                const domainTrapAction = () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.DEFINE,
                        target, property, descriptor))
                        throw new ReferenceError("Access denied");

                    return Reflect.defineProperty(target, property, descriptor);
                };

                if (isSourceDomain)
                    return domainTrapAction();

                return Marshal.#trapDomain(sourceDomain, domainTrapAction);
            },
            deleteProperty(target, p) {
                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.DELETE, target, p))
                        throw new ReferenceError("Access denied");

                    return Reflect.deleteProperty(target, p);
                });
            },
            get(target, p, receiver) {
                switch (p) {
                    case Marshal.#revertTarget:
                        return target;
                    case Marshal.#sourceDomain:
                        return sourceDomain;
                }

                const marshalledReceiver = Marshal.#marshal(receiver, sourceDomain);

                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.READ, target, p, receiver))
                        throw new ReferenceError("Access denied");

                    const result = Reflect.get(target, p, marshalledReceiver);
                    return Marshal.#marshal(result, targetDomain);
                });
            },
            getOwnPropertyDescriptor(target, p) {
                const isSourceDomain = Domain.current === sourceDomain;
                const domainTrapAction = () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.DESCRIBE, target, p))
                        throw new ReferenceError("Access denied");

                    return Reflect.getOwnPropertyDescriptor(target, p);
                };

                if (isSourceDomain)
                    return domainTrapAction();

                const descriptor = Marshal.#trapDomain(sourceDomain, domainTrapAction);

                if (descriptor == null)
                    return undefined;

                const window = targetDomain[SandboxExposer](SandboxSignal_GetWindow);
                const result = new window.Object();

                for (const key in descriptor) {
                    result[key] = Marshal.#marshal(descriptor[key], targetDomain);
                }

                return result;
            },
            getPrototypeOf(target) {
                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.TRACE, target))
                        throw new ReferenceError("Access denied");

                    const result = Reflect.getPrototypeOf(target);
                    return Marshal.#marshal(result, targetDomain);
                });
            },
            has(target, p) {
                const isSourceDomain = Domain.current === sourceDomain;
                const domainTrapAction = () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.EXISTS, target, p))
                        throw new ReferenceError("Access denied");

                    return Reflect.has(target, p);
                };

                if (isSourceDomain)
                    return domainTrapAction();

                return Marshal.#trapDomain(sourceDomain, domainTrapAction);
            },
            isExtensible(target) {
                return Reflect.isExtensible(target);
            },
            ownKeys(target) {
                const keys = Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.LIST, target))
                        throw new ReferenceError("Access denied");

                    return Reflect.ownKeys(target);
                });

                return Marshal.#marshalArray(keys, targetDomain);
            },
            preventExtensions(target) {
                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.SEAL, target))
                        throw new ReferenceError("Access denied");

                    return Reflect.preventExtensions(target);
                });
            },
            set(target, p, newValue, receiver) {
                const marshalledNewValue = Marshal.#marshal(newValue, targetDomain);
                const marshalledReceiver = Marshal.#marshal(receiver, targetDomain);

                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.WRITE,
                        target, p, newValue, receiver))
                        throw new ReferenceError("Access denied");

                    return Reflect.set(target, p, marshalledNewValue, marshalledReceiver);
                });
            },
            setPrototypeOf(target, v) {
                const marshalledV = Marshal.#marshal(v, targetDomain);

                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.META, target, v))
                        throw new ReferenceError("Access denied");

                    return Reflect.setPrototypeOf(target, marshalledV);
                });
            },
        });

        this.#marshalledProxies.add(proxy);
        targetDomain[SandboxExposer]
            (SandboxSignal_SetMarshalledProxy, target, proxy);
        return proxy;
    }

    /**
     * @param {Symbol} signal 
     * @param {...any} args 
     */
    static [SandboxExposer2](signal, ...args) {
        switch (signal) {
            case SandboxSignal_Marshal:
                return this.#marshal(...args);
            case SandboxSignal_UnpackProxy:
                return this.#revertProxy(...args);
            case SandboxSignal_TrapDomain:
                return this.#trapDomain(...args);
        }
    }
}

/**
 * ```plain
 * 运行域对象
 * 
 * 提供运行域的创建以及周期管理
 * ```
 */
class Domain {
    static #hasInstance = Object[Symbol.hasInstance];
    static #domainMap = new WeakMap();
    static #domainStack = [];
    static #currentDomain = null;
    static #topDomain = null;

    #domainObject = null;
    #domainError = null;
    #domainPromise = null;
    #domainRoot = null;
    #marshalledCached = new WeakMap();

    constructor() {
        let global = window;

        if (Domain.#currentDomain) {
            if (!createRealm)
                throw new ReferenceError("Sandbox 载入时处于不安全运行域");

            global = createRealm();
        }

        this.#domainRoot = global;
        this.#domainObject = global.Object;
        this.#domainError = global.Error;
        this.#domainPromise = global.Promise;
        Domain.#domainMap.set(global.Object, this);
        Globals.ensureDomainGlobals(this);
    }

    /**
     * ```plain
     * 检查对象是否来自于当前的运行域
     * ```
     * 
     * @param {Object} obj 
     * @returns {boolean} 
     */
    isFrom(obj) {
        if (Marshal.isMarshalled(obj)) {
            const [domain,] = Marshal[SandboxExposer2]
                (SandboxSignal_UnpackProxy, obj);
            return domain === this;
        }

        return Domain.#hasInstance
            .call(this.#domainObject, obj);
    }

    /**
     * ```plain
     * 检查对象是否来自于当前的运行域的Promise
     * ```
     * 
     * @param {Promise} promise 
     * @returns {boolean} 
     */
    isPromise(promise) {
        if (Marshal.isMarshalled(promise))
            [, promise] = Marshal[SandboxExposer2]
                (SandboxSignal_UnpackProxy, promise);

        return Domain.#hasInstance
            .call(this.#domainPromise, promise);
    }

    /**
     * ```plain
     * 检查对象是否来自于当前的运行域的Error
     * ```
     * 
     * @param {Error} error 
     * @returns {boolean} 
     */
    isError(error) {
        if (Marshal.isMarshalled(error))
            [, error] = Marshal[SandboxExposer2]
                (SandboxSignal_UnpackProxy, error);

        return Domain.#hasInstance
            .call(this.#domainError, error);
    }

    static #enterDomain(domain) {
        Domain.#domainStack.push(Domain.#currentDomain);
        Domain.#currentDomain = domain;
    }

    static #exitDomain() {
        if (Domain.#domainStack.length < 1)
            throw new ReferenceError("无法弹出更多的运行域");

        Domain.#currentDomain = Domain.#domainStack.pop();
    }

    static get current() {
        return Domain.#currentDomain;
    }

    static get topDomain() {
        return Domain.#topDomain;
    }

    /**
     * @param {Symbol} signal 
     * @param {...any} args 
     */
    [SandboxExposer](signal, ...args) {
        switch (signal) {
            case SandboxSignal_GetMarshalledProxy:
                return this.#marshalledCached.get(...args);
            case SandboxSignal_SetMarshalledProxy:
                return void this.#marshalledCached.set(...args);
            case SandboxSignal_GetWindow:
                return this.#domainRoot;
        }
    }

    /**
     * @param {Symbol} signal 
     * @param {...any} args 
     */
    static [SandboxExposer2](signal, ...args) {
        switch (signal) {
            case SandboxSignal_InitDomain:
                if (Domain.#currentDomain)
                    throw new TypeError("顶级运行域已经被初始化");

                Domain.#currentDomain = new Domain();
                Domain.#topDomain = Domain.#currentDomain;
                return;
            case SandboxSignal_EnterDomain:
                return this.#enterDomain(...args);
            case SandboxSignal_ExitDomain:
                return this.#exitDomain();
        }
    }
}

Domain[SandboxExposer2](SandboxSignal_InitDomain);

/**
 * ```plain
 * 向JavaScript提供类似于Python的exec的自带上下文的eval功能
 * 同时自动排除原有作用域以沙盒方式来执行部分代码
 * ```
 */
class Sandbox {
    #scope = {};
    #scopeStack = [];

    /** @type {Domain} */
    #domain = null;
    /** @type {Window} */
    #domainWindow = null;
    /** @type {typeof Object} */
    #domainObject = Object;
    /** @type {typeof Function} */
    #domainFunction = Function;

    /**
     * @param {Object?} initScope 用于初始化scope的对象
     */
    constructor(initScope = null) {
        this.#domain = new Domain();
        this.#domainWindow = this.#domain[SandboxExposer](SandboxSignal_GetWindow);
        this.#domainObject = this.#domainWindow.Object;
        this.#domainFunction = this.#domainWindow.Function;

        if (isPrimitive(initScope))
            initScope = null;

        this.#createScope(initScope);
    }

    /**
     * 获取当前的scope
     * 
     * @type {Object}
     */
    get scope() {
        return Marshal[SandboxExposer2]
            (SandboxSignal_Marshal, this.#scope, Domain.current);
    }

    /**
     * 获取当前沙盒内的运行域
     * 
     * @type {Domain}
     */
    get domain() {
        return this.#domain;
    }

    /**
     * 向当前域注入内建对象
     */
    initBuiltins() {
        const builtins = {
            Object: this.#domainObject,
            Function: this.#domainFunction,
            Array: this.#domainWindow.Array,
            Math: this.#domainWindow.Math,
            Date: this.#domainWindow.Date,
            String: this.#domainWindow.String,
            Number: this.#domainWindow.Number,
            Boolean: this.#domainWindow.Boolean,
            RegExp: this.#domainWindow.RegExp,
            Error: this.#domainWindow.Error,
            TypeError: this.#domainWindow.TypeError,
            RangeError: this.#domainWindow.RangeError,
            SyntaxError: this.#domainWindow.RangeError,
            EvalError: this.#domainWindow.EvalError,
            ReferenceError: this.#domainWindow.ReferenceError,
            Promise: this.#domainWindow.Promise,
            Map: this.#domainWindow.Map,
            Set: this.#domainWindow.Set,
            WeakMap: this.#domainWindow.WeakMap,
            WeakSet: this.#domainWindow.WeakSet,
            WeakRef: this.#domainWindow.WeakRef,
            Symbol: this.#domainWindow.Symbol,
            Proxy: this.#domainWindow.Proxy,
            Reflect: this.#domainWindow.Reflect,
            BigInt: this.#domainWindow.BigInt,
            JSON: this.#domainWindow.JSON,
            eval: this.#domainWindow.eval,
            setTimeout: this.#domainWindow.setTimeout,
            setInterval: this.#domainWindow.setInterval,
            setImmediate: this.#domainWindow.setImmediate,
            clearTimeout: this.#domainWindow.clearTimeout,
            clearInterval: this.#domainWindow.clearInterval,
            clearImmediate: this.#domainWindow.clearImmediate,
            alert: this.#domainWindow.alert,
            confirm: this.#domainWindow.confirm,
            console: this.#domainWindow.console,
        };

        const hardBuiltins = {
            document: this.#domainWindow.document,
            NaN: NaN,
            Infinity: Infinity,
            undefined: undefined,
        };

        for (const [k, v] of Object.entries(builtins)) {
            if (!v)
                delete builtins[k];
            if (typeof v == "function" && !v.prototype)
                builtins[k] = v.bind(null);
        }

        Object.assign(this.#scope, builtins);

        for (const [k, v] of Object.entries(hardBuiltins)) {
            Reflect.defineProperty(this.#scope, k, {
                value: v,
                writable: false,
                enumerable: false,
                configurable: false,
            });
        }

        Reflect.defineProperty(this.#scope, "window", {
            get: (() => {
                return this.#scope;
            }).bind(this),
            enumerable: false,
            configurable: false,
        });
    }

    /**
     * ```plain
     * 基于当前的scope克隆一个新的scope
     * 然后将原本的scope压入栈中
     * ```
     */
    pushScope() {
        this.#scopeStack.push(this.#scope);
        this.#createScope();
    }

    /**
     * ```plain
     * 丢弃当前的scope并从栈中弹出原本的scope
     * ```
     */
    popScope() {
        if (!this.#scopeStack)
            throw new ReferenceError("没有更多的scope可以弹出");

        this.#scope = this.#scopeStack.pop();
    }

    /**
     * ```plain
     * 基于给定的代码与当前的scope来构造一个闭包函数
     * 
     * 参数context指定临时上下文，类似与scope但是里面的变量优先级高于scope
     * 另外可以通过context.this属性来指定函数的this
     * 
     * 请注意，当沙盒闭包函数构造后，scope将被闭包固定
     * 这意味着pushScope与popScope不会影响到构造好的函数
     * ```
     * 
     * @param {string} code 沙盒闭包函数的代码
     * @param {Object} context 临时上下文
     * @returns 构造的沙盒闭包函数
     */
    compile(code, context = null) {
        if (typeof code != "string")
            throw new TypeError("代码需要是一个字符串");
        if (isPrimitive(context))
            context = {};

        const params = Object.keys(context);

        // 进行语法检查，防止注入
        try {
            new this.#domainFunction(...params, code);
        } catch (e) {
            code = "return " + code;
            new this.#domainFunction(...params, code);
        }

        const scope = this.#scope;
        const contextName = Sandbox.#makeName("__context_", scope);

        const raw = new this.#domainFunction("_", `with (_) {
            with (window) {
                with (${contextName}) {
                    return (function() {
                        ${code}
                    }).call(${contextName}.this);
                }
            }
        }`);

        const domain = this.#domain;
        const domainWindow = this.#domainWindow;
        const marshalledContext = Marshal[SandboxExposer2]
            (SandboxSignal_Marshal, context, domain);

        // 构建上下文拦截器
        const intercepter = new Proxy(scope, {
            has() {
                return true;
            },
            get(target, p) {
                switch (p) {
                    case contextName:
                        return marshalledContext;
                }

                if (p === Symbol.unscopables)
                    return undefined;
                if (!(p in target))
                    throw new domainWindow.ReferenceError(`${p} is not defined`);

                return target[p];
            },
        });

        // 构建陷入的沙盒闭包
        // 同时对返回值进行封送
        return (() => {
            const prevDomain = Domain.current;
            return Marshal[SandboxExposer2](SandboxSignal_TrapDomain,
                domain, () => {
                    const result = raw.call(null, intercepter);
                    return Marshal[SandboxExposer2]
                        (SandboxSignal_Marshal, result, prevDomain);
                });
        }).bind();
    }

    /**
     * ```plain
     * 基于当前的scope在沙盒环境下执行给定的代码
     * 
     * 参数context指定临时上下文，类似与scope但是里面的变量优先级高于scope
     * 另外可以通过context.this属性来指定函数的this
     * ```
     * 
     * @param {string} code 沙盒闭包函数的代码
     * @param {Object} context 临时上下文
     * @returns 执行代码的返回值
     */
    exec(code, context = null) {
        return this.compile(code, context)();
    }

    #createScope(initScope = null) {
        let baseScope = initScope || this.#scope;
        this.#scope = new this.#domainObject();

        Reflect.defineProperty(this.#scope, "window", {
            value: this.#scope,
            writable: false,
            enumerable: true,
            configurable: false,
        });

        if (!baseScope)
            return;

        baseScope = Marshal[SandboxExposer2]
            (SandboxSignal_Marshal, baseScope, this.#domain);

        Marshal[SandboxExposer2](SandboxSignal_TrapDomain, this.#domain, () => {
            const descriptors = Object.getOwnPropertyDescriptors(baseScope);
            delete descriptors.window;
            Object.defineProperties(this.#scope, descriptors);
        });
    }

    static #makeName(prefix, conflict) {
        let builtName;

        do {
            builtName = prefix + Math.floor(Math.random() * 100000);
        } while (builtName in conflict);

        return builtName;
    }
}

function sealClass(clazz) {
    Object.freeze(clazz);

    if (typeof clazz == "function")
        Object.freeze(clazz.prototype);
    else if (clazz.constructor)
        Object.freeze(clazz.constructor);
}

sealClass(AccessAction);
sealClass(Rule);
sealClass(Marshal);
sealClass(Domain);
sealClass(Sandbox);

const SANDBOX_EXPORT = {
    AccessAction,
    Rule,
    Marshal,
    Domain,
    Sandbox,
};

// 确保顶级运行域的原型链不暴露
if (window.top === window) {
    const document = window.document;
    const iframe = document.createElement("iframe");
    document.body.appendChild(iframe);

    Reflect.defineProperty(iframe.contentWindow, "createRealm", {
        value() {
            const iframe = document.createElement("iframe");
            document.body.appendChild(iframe);
            const window = iframe.contentWindow;
            iframe.remove();
            return window;
        },
    });

    const script = iframe.contentDocument.createElement("script");
    script.src = FILE_URL;
    script.type = "module";

    const promise = new Promise((resolve, reject) => {
        script.onload = resolve;
        script.onerror = reject;
    });
    iframe.contentDocument.head.appendChild(script);
    await promise;

    Object.assign(SANDBOX_EXPORT, iframe.contentWindow.SANDBOX_EXPORT);
    iframe.remove();
} else {
    // 防止被不信任代码更改
    sealClass(Object);
    sealClass(Array);
    sealClass(Function);
    sealClass(Promise);
    sealClass(String);
    sealClass(Number);
    sealClass(Boolean);
    sealClass(Symbol);
    sealClass(Reflect);
    sealClass(Proxy);
    sealClass(Date);
    sealClass(Math);

    window.SANDBOX_EXPORT =
        Object.assign({}, SANDBOX_EXPORT);
}

export default SANDBOX_EXPORT;