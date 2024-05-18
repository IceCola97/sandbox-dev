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
const SandboxSignal_DiapatchMonitor = Symbol("DiapatchMonitor");

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
     * ```plain
     * 创建一个封送规则
     * ```
     * 
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
 * 全局变量映射表应该用于JavaScript的内建对象
 * 因为只有内建对象才会在所有运行域同时都有
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
    "/parseInt",
    "/parseFloat",
    "/isNaN",
    "/isFinite",
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
        if (!Globals.#globals.has(domain)) {
            const window = domain[SandboxExposer](SandboxSignal_GetWindow);
            const globals = [new WeakMap(), {}];

            for (const path of GLOBAL_PATHES) {
                const [key, obj] = Globals.parseFrom(path, window);

                if (obj == null)
                    continue;

                globals[0].set(obj, key);
                globals[1][key] = obj;
            }

            Globals.#globals.set(domain, globals);
        }
    }

    /**
     * @param {Domain} domain 
     * @param {Object} obj 
     */
    static findGlobalKey(domain, obj) {
        Globals.ensureDomainGlobals(domain);
        const globals = Globals.#globals.get(domain);
        return globals[0].get(obj);
    }

    /**
     * @param {Domain} domain 
     * @param {string} key 
     */
    static findGlobalObject(domain, key) {
        Globals.ensureDomainGlobals(domain);
        const globals = Globals.#globals.get(domain);
        return globals[1][key];
    }

    /**
     * @param {Object} obj 
     * @param {Domain} sourceDomain 
     * @param {Domain} targetDomain 
     */
    static mapTo(obj, sourceDomain, targetDomain) {
        const key = Globals.findGlobalKey(sourceDomain, obj);

        if (!key)
            return undefined;

        return Globals.findGlobalObject(targetDomain, key);
    }
}

/**
 * ```plain
 * 提供封送对象的行为监控
 * ```
 */
class Monitor {
    /** @type {Object<number, Set<Monitor>>} */
    static #actionMonitors = {};
    /** @type {Set<Monitor>} */
    static #monitorSet = new Set();

    /** @type {Set<number>} */
    #actions = new Set();
    /** @type {Object<string, Set>} */
    #checkInfo = {};
    /** @type {Function?} */
    #filter = null;
    /** @type {Function?} */
    #handler = null;

    /**
     * ```plain
     * 指定 Monitor 监听的访问动作
     * ```
     * 
     * @param  {...number} action 
     * @returns {this} 
     */
    action(...action) {
        if (this.isStarted)
            throw new Error("Monitor 在启动期间不能修改");
        if (action.length == 0
            || !action.every(AccessAction.isAccessAction))
            throw new TypeError("无效的访问动作");

        for (const item of action)
            this.#actions.add(item);

        return this;
    }

    /**
     * ```plain
     * 指定 Monitor 监听的命名参数
     * 
     * 命名参数可能如下:
     * target: 监听的对象，访问动作：所有
     * thisArg: 调用的this对象，访问动作：CALL
     * arguments: 调用的参数，访问动作：CALL, NEW
     * newTarget: 构造的new.target，访问动作：NEW
     * property: 访问的属性，访问动作：DEFINE, DELETE, DESCRIBE, EXISTS, READ, WRITE
     * descriptor: 定义的属性描述符，访问动作：DEFINE
     * receiver: 设置或读取的this对象，访问动作：READ, WRITE
     * prototype: 定义的原型，访问动作：META
     * ```
     * 
     * @typedef {"target" | "thisArg" | "arguments" | "newTarget" | "property" | "descriptor" | "receiver" | "prototype"} PropertyKey
     * 
     * @param {PropertyKey} name 命名参数名称
     * @param  {...any} values 命名参数可能的值
     * @returns {this} 
     */
    require(name, ...values) {
        if (this.isStarted)
            throw new Error("Monitor 在启动期间不能修改");
        if (typeof name != "string")
            throw new TypeError("无效的检查名称");
        if (!values.length)
            return;

        let info = this.#checkInfo[name];

        if (!info)
            info = this.#checkInfo[name] = new Set();

        for (const value of values)
            info.add(value);

        return this;
    }

    /**
     * ```plain
     * 指定 Monitor 监听的过滤器
     * 
     * 回调参数 nameds 是一个对象，包含了 Monitor 监听的命名参数
     * ```
     *
     * @typedef {{
     *    target: Object,
    *     thisArg?: Object,
    *     arguments?: Array<any>,
    *     newTarget?: Function,
    *     property?: string | symbol,
    *     descriptor?: {
    *         value?: any,
    *         writable?: boolean,
    *         get?: () => any,
    *         set?: (any) => void,
    *         enumerable: boolean,
    *         configurable: boolean,
    *     },
    *     receiver?: Object,
    *     prototype?: Object,
    * }} Nameds
    * 
     * @param {(nameds: Nameds) => boolean} filter 要指定的过滤器
     * @returns {this} 
     */
    filter(filter) {
        if (this.isStarted)
            throw new Error("Monitor 在启动期间不能修改");
        if (typeof filter != "function")
            throw new TypeError("无效的过滤器");

        this.#filter = filter;
        return this;
    }

    /**
     * ```plain
     * 指定 Monitor 监听的回调函数
     * 
     * 回调参数 nameds 是一个对象，包含了 Monitor 监听的命名参数
     * 回调参数 control 是一个对象，提供本次监听的控制函数
     * control.preventDefault(value) 阻止默认的行为，并将设定的返回值作为本次代理访问的返回值
     * control.stopPropagation() 阻断后续的监听器，但不会阻止默认行为
     * control.overrideParameter(name, value) 覆盖本次监听的命名参数
     * control.setReturnValue(value) 设置本次代理访问的返回值，可以覆盖之前监听器设置的返回值
     * ```
     * 
     * @typedef {{
     *    target: Object,
    *     thisArg?: Object,
    *     arguments?: Array<any>,
    *     newTarget?: Function,
    *     property?: string | symbol,
    *     descriptor?: {
    *         value?: any,
    *         writable?: boolean,
    *         get?: () => any,
    *         set?: (any) => void,
    *         enumerable: boolean,
    *         configurable: boolean,
    *     },
    *     receiver?: Object,
    *     prototype?: Object,
    * }} Nameds
    * 
     * @typedef {{
     *     preventDefault: () => void,
     *     stopPropagation: () => void,
     *     overrideParameter: (name: string, value: any) => void,
     *     setReturnValue: (value: any) => void,
     * }} Control
     * 
     * @param {(nameds: Nameds, control: Control) => boolean} handler 
     * @returns {this} 
     */
    then(handler) {
        if (this.isStarted)
            throw new Error("Monitor 在启动期间不能修改");
        if (typeof handler != "function")
            throw new TypeError("无效的回调");

        this.#handler = handler;
        return this;
    }

    /**
     * ```plain
     * 判断 Monitor 是否已经启动
     * ```
     * 
     * @type {boolean}
     */
    get isStarted() {
        return Monitor.#monitorSet.has(this);
    }

    /**
     * ```plain
     * 启动 Monitor
     * ```
     */
    start() {
        if (this.isStarted)
            throw new Error("Monitor 已经启动");
        if (typeof this.#handler != "function")
            throw new Error("Monitor 未指定回调函数");

        Monitor.#monitorSet.add(this);

        for (const action of this.#actions) {
            let monitorMap = Monitor.#actionMonitors[action];

            if (!monitorMap)
                monitorMap = Monitor.#actionMonitors[action] = new Set();

            monitorMap.add(this);
        }
    }

    /**
     * ```plain
     * 停止 Monitor
     * ```
     */
    stop() {
        if (!this.isStarted)
            throw new Error("Monitor 还未启动");

        Monitor.#monitorSet.delete(this);

        for (const action of this.#actions) {
            let monitorMap = Monitor.#actionMonitors[action];

            if (!monitorMap)
                continue;

            monitorMap.delete(this);
        }
    }

    /**
     * @param {Object<string, any>} nameds 
     * @param {Object<string, Set>?} checkInfo 
     */
    static #check = function (nameds, checkInfo) {
        for (const [key, value] of Object.entries(nameds)) {
            if (key in checkInfo) {
                if (!checkInfo[key].has(value))
                    return false;
            }
        }

        return true;
    }

    static #dispatch = function (action, args) {
        const nameds = {};
        let indexMap;

        switch (action) {
            case AccessAction.CALL:
                indexMap = {
                    target: 0,
                    thisArg: 1,
                    arguments: 2,
                };
                break;
            case AccessAction.NEW:
                indexMap = {
                    target: 0,
                    arguments: 1,
                    newTarget: 2,
                };
                break;
            case AccessAction.DEFINE:
                indexMap = {
                    target: 0,
                    property: 1,
                    descriptor: 2,
                };
                break;
            case AccessAction.DELETE:
            case AccessAction.DESCRIBE:
            case AccessAction.EXISTS:
                indexMap = {
                    target: 0,
                    property: 1,
                };
                break;
            case AccessAction.READ:
                indexMap = {
                    target: 0,
                    property: 1,
                    receiver: 2,
                };
                break;
            case AccessAction.TRACE:
            case AccessAction.LIST:
            case AccessAction.SEAL:
                indexMap = {
                    target: 0,
                };
                break;
            case AccessAction.WRITE:
                indexMap = {
                    target: 0,
                    property: 1,
                    value: 2,
                    receiver: 3,
                };
                break;
            case AccessAction.META:
                indexMap = {
                    target: 0,
                    prototype: 1,
                };
                break;
            default:
                throw new TypeError("不支持的访问操作");
        }

        for (const key in indexMap)
            nameds[key] = args[indexMap[key]];

        Object.freeze(indexMap);
        Object.freeze(nameds);

        const monitorMap = Monitor.#actionMonitors[action];
        const result = {
            preventDefault: false,
            stopPropagation: false,
            returnValueSet: false,
            returnValue: undefined,
        };

        if (!monitorMap || monitorMap.size == 0)
            return result;

        const control = Object.freeze({
            preventDefault() {
                result.preventDefault = true;
            },
            stopPropagation() {
                result.stopPropagation = true;
            },
            overrideParameter(name, value) {
                if (!(name in indexMap))
                    throw new TypeError(`参数 ${name} 没有找到`);

                args[indexMap[name]] = value;
            },
            setReturnValue(value) {
                result.returnValueSet = true;
                result.returnValue = value;
            },
        });

        for (const monitor of monitorMap) {
            if (!Monitor.#check(nameds, monitor.#checkInfo))
                continue;

            const filter = monitor.#filter;
            if (typeof filter === 'function' && !filter(nameds))
                continue;

            monitor.#handler(nameds, control);
        }

        return result;
    }

    /**
     * @param {Symbol} signal 
     * @param  {...any} args 
     */
    static [SandboxExposer2](signal, ...args) {
        switch (signal) {
            case SandboxSignal_DiapatchMonitor:
                return Monitor.#dispatch(...args);
        }
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

    static #shouldMarshal = function (obj) {
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

    static #strictMarshal = function (obj) {
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
     * 
     * @param {any} proxy 
     * @returns {Reverted}
     */
    static #revertProxy = function (proxy) {
        return [
            proxy[Marshal.#sourceDomain],
            proxy[Marshal.#revertTarget],
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
    static #cacheProxy = function (obj, domain) {
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
    static #ensureRuleRef = function (obj) {
        let rule = Marshal.#marshalRules.get(obj);

        if (!rule)
            Marshal.#marshalRules.set(obj, rule = { rule: null });

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
        return Marshal.#marshalRules.has(obj);
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
        if (Marshal.#marshalledProxies.has(obj))
            throw new ReferenceError("无法为封送对象设置封送规则");

        const ref = Marshal.#ensureRuleRef(obj);

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
        return Marshal.#marshalledProxies.has(obj);
    }

    /**
     * ```plain
     * 陷入某个运行域并执行代码
     * ```
     * 
     * @param {Domain} domain 
     * @param {() => any} action 
     */
    static #trapDomain = function (domain, action) {
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
     * @returns {Array} 
     */
    static #marshalArray = function (array, targetDomain) {
        if (!Marshal.isMarshalled(array)
            && targetDomain.isFrom(array))
            return array;

        const window = targetDomain[SandboxExposer](SandboxSignal_GetWindow);
        const newArray = new window.Array(array.length);

        for (let i = 0; i < newArray.length; i++)
            newArray[i] = Marshal.#marshal(array[i], targetDomain);

        return newArray;
    }

    /**
     * ```plain
     * 封送对象
     * ```
     * 
     * @param {Object} object 
     * @param {Domain} targetDomain 
     * @returns {Object} 
     */
    static #marshalObject = function (object, targetDomain) {
        if (!Marshal.isMarshalled(object)
            && targetDomain.isFrom(object))
            return object;

        const window = targetDomain[SandboxExposer](SandboxSignal_GetWindow);
        const newObject = new window.Object();

        for (const key of Reflect.ownKeys(object))
            newObject[key] = Marshal.#marshal(object[key], targetDomain);

        return newObject;
    }

    /**
     * @param {Object} obj 
     * @param {Domain} targetDomain 
     * @returns {Object} 
     */
    static #marshal = function (obj, targetDomain) {
        // 基元封送
        if (isPrimitive(obj))
            return obj;

        // 尝试拆除代理
        let [sourceDomain, target] =
            Marshal.#marshalledProxies.has(obj)
                ? Marshal.#revertProxy(obj)
                : [Domain.current, obj];

        // target: 确保拆除了封送代理的对象
        // sourceDomain: target所属的运行域
        // targetDomain: 要封送到的运行域

        if (sourceDomain === targetDomain)
            return target;

        if (Marshal.#strictMarshal(target))
            throw new TypeError("对象无法封送");
        if (!Marshal.#shouldMarshal(target))
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
        const ruleRef = Marshal.#ensureRuleRef(target);
        const rule = ruleRef.rule;

        if (rule && !rule.canMarshalTo(targetDomain))
            throw new TypeError("无法将对象封送到目标运行域");

        // 检查封送缓存
        const cached = Marshal.#cacheProxy(target, targetDomain);

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

                    const args = [target, marshalledThis, marshalledArgs];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.CALL, args);

                    if (dispatched.returnValueSet)
                        return Marshal.#marshal(dispatched.returnValue, targetDomain);

                    const result = Reflect.apply(...args);
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

                    const args = [target, marshalledArgs, marshalledNewTarget];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.NEW, args);

                    if (dispatched.returnValueSet)
                        return Marshal.#marshal(dispatched.returnValue, targetDomain);

                    const result = Reflect.construct(...args);
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

                    const args = [target, property, descriptor];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.DEFINE, args);

                    if (dispatched.returnValueSet)
                        return !!dispatched.returnValue;

                    return Reflect.defineProperty(...args);
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

                    const args = [target, p];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.DELETE, args);

                    if (dispatched.returnValueSet)
                        return !!dispatched.returnValue;

                    return Reflect.deleteProperty(...args);
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

                    const args = [target, p, marshalledReceiver];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.READ, args);

                    if (dispatched.returnValueSet)
                        return Marshal.#marshal(dispatched.returnValue, targetDomain);

                    const result = Reflect.get(...args);
                    return Marshal.#marshal(result, targetDomain);
                });
            },
            getOwnPropertyDescriptor(target, p) {
                const isSourceDomain = Domain.current === sourceDomain;
                const domainTrapAction = () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.DESCRIBE, target, p))
                        throw new ReferenceError("Access denied");

                    const args = [target, p];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.DESCRIBE, args);

                    if (dispatched.returnValueSet)
                        return dispatched.returnValue;

                    return Reflect.getOwnPropertyDescriptor(...args);
                };

                if (isSourceDomain)
                    return domainTrapAction();

                const descriptor = Marshal.#trapDomain(sourceDomain, domainTrapAction);
                return Marshal.#marshalObject(descriptor, targetDomain);
            },
            getPrototypeOf(target) {
                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.TRACE, target))
                        throw new ReferenceError("Access denied");

                    const args = [target];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.TRACE, args);

                    if (dispatched.returnValueSet)
                        return Marshal.#marshal(dispatched.returnValue, targetDomain);

                    const result = Reflect.getPrototypeOf(...args);
                    return Marshal.#marshal(result, targetDomain);
                });
            },
            has(target, p) {
                const isSourceDomain = Domain.current === sourceDomain;
                const domainTrapAction = () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.EXISTS, target, p))
                        throw new ReferenceError("Access denied");

                    const args = [target, p];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.EXISTS, args);

                    if (dispatched.returnValueSet)
                        return !!dispatched.returnValue;

                    return Reflect.has(...args);
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

                    const args = [target];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.LIST, args);

                    if (dispatched.returnValueSet)
                        return dispatched.returnValue;

                    return Reflect.ownKeys(...args);
                });

                return Marshal.#marshalArray(keys, targetDomain);
            },
            preventExtensions(target) {
                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.SEAL, target))
                        throw new ReferenceError("Access denied");

                    const args = [target];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.SEAL, args);

                    if (dispatched.returnValueSet)
                        return !!dispatched.returnValue;

                    return Reflect.preventExtensions(...args);
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

                    const args = [target, p, marshalledNewValue, marshalledReceiver];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.WRITE, args);

                    if (dispatched.returnValueSet)
                        return !!dispatched.returnValue;

                    return Reflect.set(...args);
                });
            },
            setPrototypeOf(target, v) {
                const marshalledV = Marshal.#marshal(v, targetDomain);

                return Marshal.#trapDomain(sourceDomain, () => {
                    const rule = ruleRef.rule;

                    if (rule && !rule.canAccess(AccessAction.META, target, v))
                        throw new ReferenceError("Access denied");

                    const args = [target, marshalledV];
                    const dispatched = Marshal.#notifyMonitor(AccessAction.META, args);

                    if (dispatched.returnValueSet)
                        return !!dispatched.returnValue;

                    return Reflect.setPrototypeOf(...args);
                });
            },
        });

        Marshal.#marshalledProxies.add(proxy);
        targetDomain[SandboxExposer]
            (SandboxSignal_SetMarshalledProxy, target, proxy);
        return proxy;
    }

    static #notifyMonitor = function (action, args, targetDomain) {
        return Monitor[SandboxExposer2]
            (SandboxSignal_DiapatchMonitor, action, args);
    }

    /**
     * @param {Symbol} signal 
     * @param {...any} args 
     */
    static [SandboxExposer2](signal, ...args) {
        switch (signal) {
            case SandboxSignal_Marshal:
                return Marshal.#marshal(...args);
            case SandboxSignal_UnpackProxy:
                return Marshal.#revertProxy(...args);
            case SandboxSignal_TrapDomain:
                return Marshal.#trapDomain(...args);
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

    /**
     * ```plain
     * 创建运行域
     * 
     * 一般不直接使用，
     * 请考虑使用直接创建沙盒
     * ```
     */
    constructor() {
        let global = window.replacedGlobal || window;

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

    static #enterDomain = function (domain) {
        Domain.#domainStack.push(Domain.#currentDomain);
        Domain.#currentDomain = domain;
    }

    static #exitDomain = function () {
        if (Domain.#domainStack.length < 1)
            throw new ReferenceError("无法弹出更多的运行域");

        Domain.#currentDomain = Domain.#domainStack.pop();
    }

    /**
     * ```plain
     * 获取当前运行域
     * ```
     * 
     * @type {Domain}
     */
    static get current() {
        return Domain.#currentDomain;
    }

    /**
     * ```plain
     * 获取顶级运行域
     * ```
     * 
     * @type {Domain}
     */
    static get topDomain() {
        return Domain.#topDomain;
    }

    /**
     * ```plain
     * 检查当前的调用是否来自可信的运行域
     * 
     * 如果检查顶级运行域，则要求没有进行任何其他运行域的陷入
     * 如果检查非顶级运行域，则要求只有顶级运行域与给定运行域的陷入
     * ```
     * 
     * @param {Domain} domain 
     */
    static isBelievable(domain) {
        if (domain === Domain.#topDomain)
            return !Domain.#domainStack.length;

        return Domain.#domainStack.concat([Domain.#currentDomain])
            .every(d => d === Domain.#topDomain || d === domain);
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
                return Domain.#enterDomain(...args);
            case SandboxSignal_ExitDomain:
                return Domain.#exitDomain();
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
    /** @type {Document} */
    #domainDocument = null;
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
        this.#domainDocument = this.#domainWindow.document;
        this.#domainObject = this.#domainWindow.Object;
        this.#domainFunction = this.#domainWindow.Function;

        if (isPrimitive(initScope))
            initScope = null;

        Sandbox.#createScope(this, initScope);
    }

    /**
     * ```plain
     * 获取当前的scope
     * ```
     * 
     * @type {Object}
     */
    get scope() {
        return Marshal[SandboxExposer2]
            (SandboxSignal_Marshal, this.#scope, Domain.current);
    }

    /**
     * ```plain
     * 获取当前沙盒内的运行域
     * ```
     * 
     * @type {Domain}
     */
    get domain() {
        return this.#domain;
    }

    /**
     * ```plain
     * 获取当前沙盒内的document对象
     * ```
     * 
     * @type {Document}
     */
    get document() {
        return Marshal[SandboxExposer2]
            (SandboxSignal_Marshal, this.#domainDocument, Domain.current);
    }

    /**
     * ```plain
     * 设置当前沙盒内的document对象
     * ```
     * 
     * @type {Document}
     */
    set document(value) {
        this.#domainDocument = Marshal[SandboxExposer2]
            (SandboxSignal_Marshal, value, this.#domain);
    }

    /**
     * ```plain
     * 向当前域注入内建对象
     * ```
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
            parseInt: this.#domainWindow.parseInt,
            parseFloat: this.#domainWindow.parseFloat,
            isFinite: this.#domainWindow.isFinite,
            isNaN: this.#domainWindow.isNaN,
        };

        const hardBuiltins = {
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

        Reflect.defineProperty(this.#scope, "document", {
            get: (function () {
                return this;
            }).bind(this.#domainDocument),
            enumerable: false,
            configurable: false,
        });

        Reflect.defineProperty(this.#scope, "window", {
            get: (function () {
                return this;
            }).bind(this.#scope),
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
        Sandbox.#createScope(this);
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

    static #createScope = function (thiz, initScope = null) {
        let baseScope = initScope || thiz.#scope;
        thiz.#scope = new thiz.#domainObject();

        Reflect.defineProperty(thiz.#scope, "window", {
            value: thiz.#scope,
            writable: false,
            enumerable: true,
            configurable: false,
        });

        if (!baseScope)
            return;

        baseScope = Marshal[SandboxExposer2]
            (SandboxSignal_Marshal, baseScope, thiz.#domain);

        Marshal[SandboxExposer2](SandboxSignal_TrapDomain, thiz.#domain, () => {
            const descriptors = Object.getOwnPropertyDescriptors(baseScope);
            delete descriptors.window;
            Object.defineProperties(thiz.#scope, descriptors);
        });
    }

    static #makeName = function (prefix, conflict) {
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
sealClass(Monitor);
sealClass(Marshal);
sealClass(Domain);
sealClass(Sandbox);

const SANDBOX_EXPORT = {
    AccessAction,
    Rule,
    Monitor,
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
            if (!window)
                throw new ReferenceError("顶级域已经被卸载");

            iframe.remove();
            return window;
        },
    });

    iframe.contentWindow.replacedGlobal = window;

    const script = iframe.contentDocument.createElement("script");
    script.src = FILE_URL;
    script.type = "module";

    const promise = new Promise((resolve, reject) => {
        script.onload = resolve;
        script.onerror = reject;
    });
    iframe.contentDocument.head.appendChild(script);
    await promise;

    delete iframe.contentWindow.replacedGlobal;
    Object.assign(SANDBOX_EXPORT, iframe.contentWindow.SANDBOX_EXPORT);
    iframe.remove();

    ({
        AccessAction,
        Rule,
        Monitor,
        Marshal,
        Domain,
        Sandbox,
    } = SANDBOX_EXPORT);
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
    sealClass(Error);
    sealClass(TypeError);
    sealClass(ReferenceError);
    sealClass(RangeError);
    sealClass(EvalError);
    sealClass(SyntaxError);

    window.SANDBOX_EXPORT =
        Object.assign({}, SANDBOX_EXPORT);
}

export {
    AccessAction,
    Rule,
    Monitor,
    Marshal,
    Domain,
    Sandbox,
};