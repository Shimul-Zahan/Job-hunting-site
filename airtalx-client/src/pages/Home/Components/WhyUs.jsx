import Lottie from "lottie-react";
import whyusmodel from "../../../../public/whyus.json"
import { TiTick } from "react-icons/ti";

const WhyUs = () => {
    return (
        <div className="py-12">
            <div className="text-center">
                <h2 className="lg:text-5xl text-3xl text-[#287180] font-semibold pb-1">Why us?</h2>
                <p className="lg:text-xl text-lg font-semibold">From all of the platforms, these are some of the reasons for you to choose our platform</p>
            </div>
            <div className="flex items-center gap-8 pt-5">
                <div className="lg:w-3/6 w-10/12 hidden md:block">
                    <Lottie animationData={whyusmodel} />
                </div>
                <ul>
                    <li className="flex pb-2">
                        <TiTick className="bg-green-700 text-white rounded-full absolute mt-2" />
                        <span className="pl-12">All of your given datas will be safe and secured</span>
                    </li>
                    <li className="flex pb-2">
                        <TiTick className="bg-green-700 text-white rounded-full absolute mt-2" />
                        <span className="pl-12">Easy and safe payment methods via your bank accounts</span></li>
                    <li className="flex pb-2">
                        <TiTick className="bg-green-700 text-white rounded-full absolute mt-2" />
                        <span className="pl-12">Access to a wide range of job opportunities across various industries and locations</span>
                    </li>
                    <li className="flex pb-2">
                        <TiTick className="bg-green-700 text-white rounded-full absolute mt-2" />
                        <span className="pl-12">Professional support and guidance throughout your job search journey</span>
                    </li>
                    <li className="flex pb-2">
                        <TiTick className="bg-green-700 text-white rounded-full absolute mt-2" />
                        <span className="pl-12">Regular updates on the latest job openings and trends in the job market</span>
                    </li>
                    <li className="flex pb-2">
                        <TiTick className="bg-green-700 text-white rounded-full absolute mt-2" />
                        <span className="pl-12">Opportunities for skill development and career advancement</span>
                    </li>
                    <li className="flex pb-2">
                        <TiTick className="bg-green-700 text-white rounded-full absolute mt-2" />
                        <span className="pl-12">Interactive tools and resources to enhance your job search experience</span>
                    </li>
                </ul>

            </div>
        </div>
    );
};

export default WhyUs;