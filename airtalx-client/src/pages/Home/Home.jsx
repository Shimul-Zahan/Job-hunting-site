import Banner from "./Components/Banner";
import MainPoints from "./Components/MainPoints";
import Steps from "./Components/Steps";
import WhyUs from "./Components/WhyUs";

const Home = () => {
    return (
        <div className="lg:w-3/4 w-11/12 mx-auto">
            <Banner/>
            <WhyUs/>
            <MainPoints/>
            <Steps/>
        </div>
    );
};

export default Home;